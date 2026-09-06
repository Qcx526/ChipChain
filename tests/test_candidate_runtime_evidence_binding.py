"""Source-reprojection tests for Phase 10D 2D4-B1 runtime evidence."""

from __future__ import annotations

import hashlib
from pathlib import Path
import runpy

from pydantic import ValidationError
import pytest

from chipchain.analysis import (
    StaticHardwareReferenceCatalog, StaticSemanticInstructionFact,
    StaticSemanticInventory, StaticTriggerCase, StaticTriggerPattern,
    StaticTriggerPatternCatalog, StaticTriggerPosition, StaticTriggerPredicate,
    bind_static_trigger_candidates_to_hardware_references,
    fuse_static_semantic_and_program_structure, project_static_semantic_inventory,
    project_static_trigger_candidates,
)

from chipchain.models import Architecture
from chipchain.runtime import (
    RuntimeBackendKind,
    RuntimeBackendManifest,
    RuntimeCapability,
    RuntimeEventKind,
    RuntimeObservation,
    RuntimeRunMode,
    RuntimeTrace,
    RuntimeTraceManifest,
)
from chipchain.verification import (
    CandidateRuntimeEvidenceGapReason,
    CandidateRuntimeEvidenceMaterialization,
    CandidateRuntimeEvidenceProjection,
    CandidateRuntimeInstructionEvidence,
    CandidateRuntimeOrderEvidence,
    CandidateRuntimeRequirementEvidenceBinding,
    CandidateRuntimeTraceIncompatibility,
    StaticCrossLayerEvidenceRequirementKind,
    bind_candidate_runtime_evidence,
    project_cross_layer_verification_requirements,
)
from chipchain.verification.candidate_runtime_evidence_binding import (
    candidate_runtime_evidence_materialization_id,
)
from chipchain.verification.candidate_runtime_evidence_models import (
    candidate_runtime_instruction_evidence_id,
    candidate_runtime_order_evidence_id,
    candidate_runtime_requirement_evidence_binding_id,
)


ROOT = Path(__file__).resolve().parents[1]
_FIXTURE_METADATA = {
    "fixture": True,
    "not_benchmark": True,
    "not_real_vulnerability": True,
    "owned": True,
    "synthetic": True,
}
_RUNNER = runpy.run_path(
    str(ROOT / "scripts/export_candidate_runtime_evidence.py"),
    run_name="phase10d_candidate_runtime_evidence_binding_runner",
)
_REQUIREMENT_RUNNER = runpy.run_path(
    str(ROOT / "scripts/export_cross_layer_verification_requirements.py"),
    run_name="phase10d_candidate_runtime_evidence_requirement_runner",
)


@pytest.fixture(scope="module")
def requirements():
    return _REQUIREMENT_RUNNER[
        "build_owned_verification_requirement_materialization"
    ]()


@pytest.fixture(scope="module")
def owned_trace():
    return RuntimeTrace.model_validate_json(_RUNNER["TRACE_PATH"].read_bytes())


@pytest.fixture(scope="module")
def owned(requirements, owned_trace):
    return bind_candidate_runtime_evidence(requirements, [owned_trace])


def _trace(
    requirements,
    observations: list[tuple[str, int]],
    *,
    run_id: str,
    architecture: Architecture | str | None = None,
    artifact_id: str | None = None,
    artifact_sha256: str | None = None,
) -> RuntimeTrace:
    projection = requirements.projection
    trace_architecture = Architecture(architecture or projection.architecture)
    backend = RuntimeBackendManifest.create(
        backend_kind=RuntimeBackendKind.OWNED_FIXTURE,
        backend_name=f"owned-phase10d-b1-{run_id}",
        backend_version="1",
        architecture=trace_architecture,
        system_emulation=False,
        capabilities=[RuntimeCapability.INSTRUCTION_EXECUTION],
        metadata=_FIXTURE_METADATA,
    )
    manifest = RuntimeTraceManifest.create(
        run_id=run_id,
        scenario_id=f"owned-synthetic-{run_id}",
        architecture=trace_architecture,
        backend_manifest_id=backend.id,
        run_mode=RuntimeRunMode.BASELINE,
        artifact_id=artifact_id or projection.artifact_id,
        artifact_sha256=artifact_sha256 or projection.artifact_sha256,
        machine="owned-synthetic-contract-machine",
        cpu="owned-synthetic-contract-cpu",
        vcpu_count=max((vcpu for _, vcpu in observations), default=0) + 1,
        metadata=_FIXTURE_METADATA,
    )
    runtime_observations = [
        RuntimeObservation.create(
            trace_id=manifest.id,
            architecture=trace_architecture,
            sequence_index=index,
            vcpu_index=vcpu,
            event_kind=RuntimeEventKind.INSTRUCTION_EXEC,
            pc=pc,
            metadata=_FIXTURE_METADATA,
        )
        for index, (pc, vcpu) in enumerate(observations)
    ]
    return RuntimeTrace(
        backend_manifest=backend,
        manifest=manifest,
        observations=runtime_observations,
    )


def _rehash_instruction(payload: dict) -> None:
    payload["id"] = candidate_runtime_instruction_evidence_id(
        {key: value for key, value in payload.items() if key != "id"}
    )


def _rehash_order(payload: dict) -> None:
    payload["id"] = candidate_runtime_order_evidence_id(
        {key: value for key, value in payload.items() if key != "id"}
    )


def _rehash_binding(payload: dict) -> None:
    payload["id"] = candidate_runtime_requirement_evidence_binding_id(
        {key: value for key, value in payload.items() if key != "id"}
    )


def _rebuild_projection(payload: dict) -> CandidateRuntimeEvidenceProjection:
    return CandidateRuntimeEvidenceProjection.create(
        **{
            key: value
            for key, value in payload.items()
            if key not in {"contract", "id", "diagnostic_codes"}
        }
    )


def _outer_payload(
    materialization: CandidateRuntimeEvidenceMaterialization,
    projection: CandidateRuntimeEvidenceProjection,
) -> dict:
    payload = materialization.model_dump(mode="json")
    payload["projection"] = projection.model_dump(mode="json")
    payload["id"] = candidate_runtime_evidence_materialization_id(
        {key: value for key, value in payload.items() if key != "id"}
    )
    return payload


def _replace_evidence_and_bindings(
    materialization: CandidateRuntimeEvidenceMaterialization,
    *,
    collection: str,
    index: int,
    updated_evidence: dict,
) -> CandidateRuntimeEvidenceProjection:
    projection = materialization.projection.model_dump(mode="json")
    old_id = projection[collection][index]["id"]
    projection[collection][index] = updated_evidence
    for binding in projection["requirement_evidence_bindings"]:
        if binding["source_runtime_evidence_id"] == old_id:
            binding["source_runtime_evidence_id"] = updated_evidence["id"]
            _rehash_binding(binding)
    return _rebuild_projection(projection)


def _candidate_and_requirement(requirements, kind, *, candidate_index: int):
    candidates = (
        requirements.source_cross_layer_candidate_materialization_snapshot
        .source_candidate_materialization_snapshot.projection.case_candidates
    )
    candidate = candidates[candidate_index]
    requirement = next(
        item
        for item in requirements.projection.candidate_requirements
        if item.source_case_candidate_id == candidate.id
        and item.evidence_requirement_kind is kind
    )
    return candidate, requirement


def test_owned_complete_mapping_counts_and_exact_source_provenance(owned) -> None:
    projection = owned.projection
    assert len(projection.source_runtime_trace_ids) == 1
    assert len(projection.compatible_runtime_trace_ids) == 1
    assert len(projection.incompatible_runtime_sources) == 0
    assert len(projection.instruction_evidence) == 6
    assert len(projection.order_evidence) == 6
    assert len(projection.requirement_evidence_bindings) == 26
    assert projection.evidence_gaps == []
    assert len(projection.out_of_scope_requirement_ids) == 12
    observations = {
        item.id: item
        for item in owned.source_runtime_trace_snapshots[0].observations
    }
    for evidence in projection.instruction_evidence:
        observation = observations[evidence.source_runtime_observation_id]
        assert evidence.observed_pc == observation.pc
        assert evidence.observation_sequence_index == observation.sequence_index
        assert evidence.observation_vcpu_index == observation.vcpu_index


def test_owned_fixture_bytes_and_synthetic_provenance_are_hash_bound(
    owned_trace,
) -> None:
    fixture_directory = _RUNNER["TRACE_PATH"].parent
    expected_hash, filename = (
        (fixture_directory / "SHA256SUMS").read_text(encoding="utf-8").split()
    )
    fixture_bytes = (fixture_directory / filename).read_bytes()
    assert hashlib.sha256(fixture_bytes).hexdigest() == expected_hash
    assert owned_trace.backend_manifest.backend_kind is RuntimeBackendKind.OWNED_FIXTURE
    assert owned_trace.manifest.run_mode is RuntimeRunMode.BASELINE
    for metadata in (
        owned_trace.backend_manifest.metadata,
        owned_trace.manifest.metadata,
        *(item.metadata for item in owned_trace.observations),
    ):
        assert metadata == _FIXTURE_METADATA


def test_exact_pc_only_no_range_or_nearest_address(requirements) -> None:
    trace = _trace(
        requirements,
        [("0x400001", 0), ("0x3fffff", 0)],
        run_id="no-address-range-inference",
    )
    result = bind_candidate_runtime_evidence(requirements, [trace]).projection
    assert result.instruction_evidence == []
    assert result.order_evidence == []
    assert {
        item.reason for item in result.evidence_gaps
    } == {
        CandidateRuntimeEvidenceGapReason.NO_MATCHING_INSTRUCTION_OBSERVATION,
        CandidateRuntimeEvidenceGapReason.NO_MATCHING_RUNTIME_ORDER_OBSERVATION,
    }


def test_multiple_observations_at_same_pc_are_all_preserved(requirements) -> None:
    trace = _trace(
        requirements,
        [("0x400000", 0), ("0x400000", 0), ("0x400000", 0)],
        run_id="repeated-exact-pc",
    )
    result = bind_candidate_runtime_evidence(requirements, [trace]).projection
    assert len(result.instruction_evidence) == 3
    assert len({item.id for item in result.instruction_evidence}) == 3
    assert len({item.source_runtime_observation_id for item in result.instruction_evidence}) == 3


def test_partial_runtime_observations_are_retained_without_outcome(requirements) -> None:
    trace = _trace(
        requirements,
        [("0x400008", 0)],
        run_id="partial-runtime-observation",
    )
    result = bind_candidate_runtime_evidence(requirements, [trace]).projection
    assert len(result.instruction_evidence) == 1
    assert result.order_evidence == []
    assert len(result.requirement_evidence_bindings) == 2
    assert len(result.evidence_gaps) == 3
    gaps = {item.source_requirement_id: item.reason for item in result.evidence_gaps}
    for index in (0, 1):
        _, runtime = _candidate_and_requirement(
            requirements, StaticCrossLayerEvidenceRequirementKind.RUNTIME_EXECUTION_TRACE_REQUIRED,
            candidate_index=index,
        )
        _, path = _candidate_and_requirement(
            requirements, StaticCrossLayerEvidenceRequirementKind.PATH_FEASIBILITY_EVIDENCE_REQUIRED,
            candidate_index=index,
        )
        assert gaps.get(runtime.id) == (
            None if index == 0 else CandidateRuntimeEvidenceGapReason.NO_MATCHING_INSTRUCTION_OBSERVATION
        )
        assert gaps[path.id] is CandidateRuntimeEvidenceGapReason.NO_MATCHING_RUNTIME_ORDER_OBSERVATION


def test_empty_trace_list_produces_requirement_specific_gaps(requirements) -> None:
    result = bind_candidate_runtime_evidence(requirements, []).projection
    assert result.instruction_evidence == result.order_evidence == []
    assert len(result.evidence_gaps) == 4
    assert all(
        item.reason is CandidateRuntimeEvidenceGapReason.NO_COMPATIBLE_RUNTIME_TRACE
        for item in result.evidence_gaps
    )


def test_compatible_unrelated_trace_has_typed_no_match_gaps(requirements) -> None:
    trace = _trace(
        requirements,
        [("0x700000", 0)],
        run_id="compatible-unrelated-pcs",
    )
    result = bind_candidate_runtime_evidence(requirements, [trace]).projection
    assert result.compatible_runtime_trace_ids == [trace.manifest.id]
    assert result.instruction_evidence == result.order_evidence == []
    assert len(result.evidence_gaps) == 4
    assert {item.reason for item in result.evidence_gaps} == {
        CandidateRuntimeEvidenceGapReason.NO_MATCHING_INSTRUCTION_OBSERVATION,
        CandidateRuntimeEvidenceGapReason.NO_MATCHING_RUNTIME_ORDER_OBSERVATION,
    }


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        (
            {"architecture": Architecture.RISC_V},
            "architecture_mismatch",
        ),
        (
            {"artifact_id": "owned-synthetic-foreign-artifact"},
            "artifact_id_mismatch",
        ),
        (
            {"artifact_sha256": "f" * 64},
            "artifact_sha256_mismatch",
        ),
    ],
)
def test_incompatible_trace_is_retained_and_excluded(
    requirements, overrides, reason
) -> None:
    trace = _trace(
        requirements,
        [("0x400000", 0)],
        run_id=f"incompatible-{reason}",
        **overrides,
    )
    result = bind_candidate_runtime_evidence(requirements, [trace]).projection
    assert result.compatible_runtime_trace_ids == []
    assert result.source_runtime_trace_ids == [trace.manifest.id]
    assert len(result.incompatible_runtime_sources) == 1
    assert reason in {
        item.value for item in result.incompatible_runtime_sources[0].reasons
    }
    assert result.instruction_evidence == result.order_evidence == []


def test_mixed_trace_order_is_deterministic_and_uses_only_compatible(
    requirements, owned_trace
) -> None:
    incompatible = _trace(
        requirements,
        [("0x400000", 0)],
        run_id="mixed-foreign-artifact",
        artifact_id="owned-synthetic-foreign-artifact",
    )
    first = bind_candidate_runtime_evidence(
        requirements, [owned_trace, incompatible]
    )
    second = bind_candidate_runtime_evidence(
        requirements, [incompatible, owned_trace]
    )
    assert first == second
    assert first.projection.compatible_runtime_trace_ids == [
        owned_trace.manifest.id
    ]
    assert all(
        item.source_runtime_trace_id == owned_trace.manifest.id
        for item in [
            *first.projection.instruction_evidence,
            *first.projection.order_evidence,
        ]
    )


def test_duplicate_trace_ids_fail_closed(requirements, owned_trace) -> None:
    with pytest.raises((ValidationError, ValueError), match="trace IDs must be unique"):
        bind_candidate_runtime_evidence(requirements, [owned_trace, owned_trace])


def test_caller_mutation_cannot_change_retained_snapshots(
    requirements, owned_trace
) -> None:
    caller_trace = RuntimeTrace.model_validate(owned_trace.model_dump(mode="json"))
    result = bind_candidate_runtime_evidence(requirements, [caller_trace])
    before = result.model_dump(mode="json")
    caller_trace.observations.clear()
    caller_trace.manifest.metadata["caller_mutation"] = True
    assert result.model_dump(mode="json") == before


def test_reverse_order_and_cross_vcpu_do_not_create_order_evidence(
    requirements,
) -> None:
    reverse = _trace(
        requirements,
        [("0x400008", 0), ("0x400000", 0)],
        run_id="reverse-endpoint-order",
    )
    cross_vcpu = _trace(
        requirements,
        [("0x400000", 0), ("0x400008", 1)],
        run_id="cross-vcpu-endpoints",
    )
    assert bind_candidate_runtime_evidence(
        requirements, [reverse]
    ).projection.order_evidence == []
    assert bind_candidate_runtime_evidence(
        requirements, [cross_vcpu]
    ).projection.order_evidence == []


def test_cross_trace_endpoints_do_not_create_order_evidence(requirements) -> None:
    source = _trace(
        requirements, [("0x400000", 0)], run_id="cross-trace-source"
    )
    target = _trace(
        requirements, [("0x400008", 0)], run_id="cross-trace-target"
    )
    result = bind_candidate_runtime_evidence(
        requirements, [source, target]
    ).projection
    assert result.order_evidence == []


def test_all_legitimate_same_trace_same_vcpu_pairs_are_retained(owned) -> None:
    pairs = {
        (
            item.source_runtime_observation_id,
            item.target_runtime_observation_id,
            item.source_static_order_witness_id,
        )
        for item in owned.projection.order_evidence
    }
    assert len(pairs) == len(owned.projection.order_evidence) == 6
    assert all(
        item.source_sequence_index < item.target_sequence_index
        and item.vcpu_index == 0
        for item in owned.projection.order_evidence
    )


def test_fully_rehashed_foreign_observation_is_rejected(owned) -> None:
    evidence = owned.projection.instruction_evidence[0].model_dump(mode="json")
    evidence["source_runtime_observation_id"] = "runtime-observation:" + "f" * 64
    _rehash_instruction(evidence)
    projection = _replace_evidence_and_bindings(
        owned,
        collection="instruction_evidence",
        index=0,
        updated_evidence=evidence,
    )
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        CandidateRuntimeEvidenceMaterialization.model_validate(
            _outer_payload(owned, projection)
        )


def test_fully_rehashed_foreign_pc_is_rejected(owned) -> None:
    evidence = owned.projection.instruction_evidence[0].model_dump(mode="json")
    evidence["expected_instruction_address"] = {"value": "0x400004"}
    evidence["observed_pc"] = {"value": "0x400004"}
    _rehash_instruction(evidence)
    projection = _replace_evidence_and_bindings(
        owned,
        collection="instruction_evidence",
        index=0,
        updated_evidence=evidence,
    )
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        CandidateRuntimeEvidenceMaterialization.model_validate(
            _outer_payload(owned, projection)
        )


def test_fully_rehashed_foreign_sequence_index_is_rejected(owned) -> None:
    evidence = owned.projection.order_evidence[0].model_dump(mode="json")
    evidence["target_sequence_index"] += 100
    _rehash_order(evidence)
    projection = _replace_evidence_and_bindings(
        owned,
        collection="order_evidence",
        index=0,
        updated_evidence=evidence,
    )
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        CandidateRuntimeEvidenceMaterialization.model_validate(
            _outer_payload(owned, projection)
        )


def test_fully_rehashed_wrong_requirement_binding_is_rejected(
    owned, requirements
) -> None:
    projection = owned.projection.model_dump(mode="json")
    evidence = next(
        item
        for item in owned.projection.instruction_evidence
        if item.observed_pc.value == "0x400008"
    )
    _, target = _candidate_and_requirement(
        requirements,
        StaticCrossLayerEvidenceRequirementKind.RUNTIME_EXECUTION_TRACE_REQUIRED,
        candidate_index=1,
    )
    binding = next(
        item
        for item in projection["requirement_evidence_bindings"]
        if item["source_runtime_evidence_id"] == evidence.id
    )
    binding["source_requirement_id"] = target.id
    binding["source_requirement_kind"] = target.evidence_requirement_kind.value
    binding["source_case_candidate_id"] = target.source_case_candidate_id
    _rehash_binding(binding)
    forged = _rebuild_projection(projection)
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        CandidateRuntimeEvidenceMaterialization.model_validate(
            _outer_payload(owned, forged)
        )


def test_fully_rehashed_wrong_subject_fact_is_rejected(owned) -> None:
    projection = owned.projection.model_dump(mode="json")
    first = projection["instruction_evidence"][0]
    other = next(
        item
        for item in projection["instruction_evidence"]
        if item["observed_pc"]["value"] != first["observed_pc"]["value"]
    )
    first["source_position_candidate_ids"] = other[
        "source_position_candidate_ids"
    ]
    first["source_fused_fact_node_ids"] = other["source_fused_fact_node_ids"]
    old_id = first["id"]
    _rehash_instruction(first)
    for binding in projection["requirement_evidence_bindings"]:
        if binding["source_runtime_evidence_id"] == old_id:
            binding["source_runtime_evidence_id"] = first["id"]
            _rehash_binding(binding)
    forged = _rebuild_projection(projection)
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        CandidateRuntimeEvidenceMaterialization.model_validate(
            _outer_payload(owned, forged)
        )


def _forge_order(
    requirements,
    materialization,
    *,
    source_trace: RuntimeTrace,
    target_trace: RuntimeTrace,
    vcpu_index: int,
) -> CandidateRuntimeEvidenceProjection:
    candidate, requirement = _candidate_and_requirement(
        requirements,
        StaticCrossLayerEvidenceRequirementKind.PATH_FEASIBILITY_EVIDENCE_REQUIRED,
        candidate_index=0,
    )
    witness = candidate.order_witnesses[0]
    positions = {item.id: item for item in candidate.position_candidates}
    source_position = positions[witness.source_position_candidate_id]
    target_position = positions[witness.target_position_candidate_id]
    source_observation = source_trace.observations[0]
    target_observation = target_trace.observations[-1]
    projection = materialization.projection
    order = CandidateRuntimeOrderEvidence.create(
        architecture=projection.architecture,
        artifact_id=projection.artifact_id,
        artifact_sha256=projection.artifact_sha256,
        instruction_set=projection.instruction_set,
        source_runtime_trace_id=source_trace.manifest.id,
        source_runtime_manifest_id=source_trace.manifest.id,
        source_runtime_backend_manifest_id=source_trace.backend_manifest.id,
        source_runtime_backend_kind=source_trace.backend_manifest.backend_kind,
        source_runtime_run_mode=source_trace.manifest.run_mode,
        source_static_order_witness_id=witness.id,
        source_position_candidate_id=source_position.id,
        target_position_candidate_id=target_position.id,
        source_fused_fact_node_id=source_position.source_fused_fact_node_id,
        target_fused_fact_node_id=target_position.source_fused_fact_node_id,
        expected_source_instruction_address=source_observation.pc,
        expected_target_instruction_address=target_observation.pc,
        source_runtime_observation_id=source_observation.id,
        target_runtime_observation_id=target_observation.id,
        source_sequence_index=source_observation.sequence_index,
        target_sequence_index=source_observation.sequence_index + 1,
        vcpu_index=vcpu_index,
    )
    binding = CandidateRuntimeRequirementEvidenceBinding.create(
        source_requirement_materialization_id=requirements.id,
        source_requirement_projection_id=requirements.projection.id,
        source_requirement_id=requirement.id,
        source_requirement_kind=requirement.evidence_requirement_kind,
        source_case_candidate_id=requirement.source_case_candidate_id,
        source_runtime_evidence_id=order.id,
    )
    values = projection.model_dump(mode="python", exclude={"contract", "id", "diagnostic_codes"})
    values["order_evidence"] = [*projection.order_evidence, order]
    values["requirement_evidence_bindings"] = [
        *projection.requirement_evidence_bindings,
        binding,
    ]
    values["evidence_gaps"] = [
        gap for gap in projection.evidence_gaps if gap.source_requirement_id != requirement.id
    ]
    return CandidateRuntimeEvidenceProjection.create(**values)


def test_fully_rehashed_cross_vcpu_forged_order_is_rejected(requirements) -> None:
    trace = _trace(
        requirements,
        [("0x400000", 0), ("0x400008", 1)],
        run_id="forged-cross-vcpu-order",
    )
    materialization = bind_candidate_runtime_evidence(requirements, [trace])
    forged = _forge_order(
        requirements,
        materialization,
        source_trace=trace,
        target_trace=trace,
        vcpu_index=0,
    )
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        CandidateRuntimeEvidenceMaterialization.model_validate(
            _outer_payload(materialization, forged)
        )


def test_fully_rehashed_cross_trace_forged_order_is_rejected(requirements) -> None:
    source = _trace(
        requirements, [("0x400000", 0)], run_id="forged-cross-trace-source"
    )
    target = _trace(
        requirements, [("0x400008", 0)], run_id="forged-cross-trace-target"
    )
    materialization = bind_candidate_runtime_evidence(
        requirements, [source, target]
    )
    forged = _forge_order(
        requirements,
        materialization,
        source_trace=source,
        target_trace=target,
        vcpu_index=0,
    )
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        CandidateRuntimeEvidenceMaterialization.model_validate(
            _outer_payload(materialization, forged)
        )


def test_invalid_and_different_valid_requirement_source_tamper_rejected(
    owned,
) -> None:
    invalid = owned.model_dump(mode="json")
    invalid["source_requirement_materialization_snapshot"]["projection"][
        "artifact_id"
    ] = "owned-synthetic-tampered-artifact"
    invalid["id"] = candidate_runtime_evidence_materialization_id(
        {key: value for key, value in invalid.items() if key != "id"}
    )
    with pytest.raises(ValidationError):
        CandidateRuntimeEvidenceMaterialization.model_validate(invalid)

    public = _REQUIREMENT_RUNNER[
        "build_public_a77_verification_requirement_materialization"
    ]()
    different = owned.model_dump(mode="json")
    different["source_requirement_materialization_id"] = public.id
    different["source_requirement_materialization_snapshot"] = public.model_dump(
        mode="json"
    )
    different["id"] = candidate_runtime_evidence_materialization_id(
        {key: value for key, value in different.items() if key != "id"}
    )
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        CandidateRuntimeEvidenceMaterialization.model_validate(different)


@pytest.mark.parametrize("field", ["pc", "sequence_index"])
def test_valid_runtime_source_snapshot_tamper_rejected_by_reprojection(
    owned, field
) -> None:
    payload = owned.model_dump(mode="json")
    trace_payload = payload["source_runtime_trace_snapshots"][0]
    old = trace_payload["observations"][0]
    values = {
        key: value
        for key, value in old.items()
        if key not in {"id", "pc", "sequence_index"}
    }
    values["pc"] = (
        "0x400004" if field == "pc" else old["pc"]["value"]
    )
    values["sequence_index"] = 100 if field == "sequence_index" else old["sequence_index"]
    replacement = RuntimeObservation.create(**values)
    trace_payload["observations"][0] = replacement.model_dump(mode="json")
    payload["id"] = candidate_runtime_evidence_materialization_id(
        {key: value for key, value in payload.items() if key != "id"}
    )
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        CandidateRuntimeEvidenceMaterialization.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("vcpu_index", 1, "vCPU index is out of range"),
        ("trace_id", "runtime-trace:" + "e" * 64, "trace identity mismatch"),
    ],
)
def test_invalid_runtime_source_snapshot_tamper_rejected_by_runtime_contract(
    owned, field, value, message
) -> None:
    payload = owned.model_dump(mode="json")
    observation = payload["source_runtime_trace_snapshots"][0]["observations"][0]
    observation[field] = value
    values = {key: item for key, item in observation.items() if key != "id"}
    values["pc"] = observation["pc"]["value"]
    observation["id"] = RuntimeObservation.create(**values).id
    payload["id"] = candidate_runtime_evidence_materialization_id(
        {key: item for key, item in payload.items() if key != "id"}
    )
    with pytest.raises(ValidationError, match=message):
        CandidateRuntimeEvidenceMaterialization.model_validate(payload)


def test_unsupported_candidate_requirements_get_one_gap_each() -> None:
    namespace = runpy.run_path(
        str(ROOT / "tests/test_cross_layer_verification_requirements.py"),
        run_name="phase10d_candidate_runtime_unsupported_source",
    )
    public_source = namespace[
        "build_public_a77_static_cross_layer_materialization"
    ]()
    requirements = project_cross_layer_verification_requirements(
        namespace["_all_obligation_source"](public_source)
    )
    result = bind_candidate_runtime_evidence(requirements, []).projection
    unsupported = [
        item
        for item in requirements.projection.candidate_requirements
        if item.evidence_requirement_kind
        not in {
            StaticCrossLayerEvidenceRequirementKind
            .RUNTIME_EXECUTION_TRACE_REQUIRED,
            StaticCrossLayerEvidenceRequirementKind
            .PATH_FEASIBILITY_EVIDENCE_REQUIRED,
        }
    ]
    gaps = [
        item
        for item in result.evidence_gaps
        if item.reason
        is CandidateRuntimeEvidenceGapReason
        .CURRENT_RUNTIME_CONTRACT_DOES_NOT_OBSERVE_REQUIREMENT_KIND
    ]
    assert len(unsupported) == len(gaps) == 4
    assert {item.source_requirement_id for item in gaps} == {
        item.id for item in unsupported
    }
    assert len(result.out_of_scope_requirement_ids) == 3


def test_public_a77_has_zero_candidate_runtime_evidence(owned_trace) -> None:
    public = _REQUIREMENT_RUNNER[
        "build_public_a77_verification_requirement_materialization"
    ]()
    result = bind_candidate_runtime_evidence(public, [owned_trace]).projection
    assert result.instruction_evidence == []
    assert result.order_evidence == []
    assert result.requirement_evidence_bindings == []
    assert result.evidence_gaps == []


def test_ten_runs_and_trace_permutations_are_identical(
    requirements, owned_trace
) -> None:
    second = _trace(
        requirements,
        [("0x700000", 0)],
        run_id="deterministic-second-trace",
    )
    values = [
        bind_candidate_runtime_evidence(requirements, [owned_trace, second])
        for _ in range(10)
    ]
    reversed_value = bind_candidate_runtime_evidence(
        requirements, [second, owned_trace]
    )
    assert len({item.id for item in values}) == 1
    assert len({item.projection.id for item in values}) == 1
    assert all(item == values[0] for item in values)
    assert reversed_value == values[0]


def _requirements_for_pattern(fused, pattern):
    candidates = project_static_trigger_candidates(
        fused, StaticTriggerPatternCatalog.create(patterns=[pattern])
    )
    return project_cross_layer_verification_requirements(
        bind_static_trigger_candidates_to_hardware_references(
            candidates, StaticHardwareReferenceCatalog.create(references=[])
        )
    )


def _alternative_requirements(requirements, *, shared_witness: bool):
    fused = (requirements.source_cross_layer_candidate_materialization_snapshot
             .source_candidate_materialization_snapshot.source_fused_graph_materialization_snapshot)
    facts = {n.operation.value: n for n in fused.projection.nodes if n.instruction_address}
    operations = ["system_register_read", "memory_barrier", "instruction_barrier"]
    positions = []
    for index, operation in enumerate(operations, 1):
        alternatives = [StaticTriggerPredicate.create(operation=operation)]
        if index == (3 if shared_witness else 1):
            alternatives.append(StaticTriggerPredicate.create(
                operation=operation, required_attributes=facts[operation].attributes,
            ))
        positions.append(StaticTriggerPosition.create(position_index=index, alternatives=alternatives))
    pattern = StaticTriggerPattern.create(
        architecture="arm", instruction_set="aarch64",
        pattern_name="owned_synthetic_b1_r1_alternatives",
        source_reference_ids=["owned-synthetic-b1-r1-source"],
        hardware_reference_ids=["owned-synthetic-b1-r1-hardware"],
        cases=[StaticTriggerCase.create(case_reference_id="owned-b1-r1-case", positions=positions)],
    )
    return _requirements_for_pattern(fused, pattern)


@pytest.mark.parametrize("shared_witness, expected_atoms", [(True, 1), (False, 2)])
def test_order_catalog_shared_witness_and_distinct_witness_provenance(
    requirements, shared_witness, expected_atoms
) -> None:
    source = _alternative_requirements(requirements, shared_witness=shared_witness)
    trace = _trace(source, [("0x400000", 0), ("0x400008", 0)], run_id="owned-r1-witness-reuse")
    result = bind_candidate_runtime_evidence(source, [trace])
    projection = result.projection
    assert len(projection.order_evidence) == expected_atoms
    order_ids = {item.id for item in projection.order_evidence}
    links = [b for b in projection.requirement_evidence_bindings if b.source_runtime_evidence_id in order_ids]
    assert len(links) == 2
    assert len({b.source_requirement_id for b in links}) == 2
    assert len({b.source_runtime_evidence_id for b in links}) == expected_atoms
    assert len({(o.source_runtime_observation_id, o.target_runtime_observation_id) for o in projection.order_evidence}) == 1
    assert len({o.source_static_order_witness_id for o in projection.order_evidence}) == expected_atoms
    assert CandidateRuntimeEvidenceMaterialization.model_validate(result.model_dump(mode="json")) == result


def test_duplicate_static_address_preserves_all_exact_subjects(requirements) -> None:
    fused = (requirements.source_cross_layer_candidate_materialization_snapshot
             .source_candidate_materialization_snapshot.source_fused_graph_materialization_snapshot)
    inventory = fused.source_semantic_graph_materialization.source_inventory_snapshot
    original = next(f for f in inventory.facts if f.instruction_address == "0x400000")
    values = original.model_dump(mode="python", exclude={"contract", "id"})
    values["operation"] = "system_register_write"
    second = StaticSemanticInstructionFact.create(**values)
    new_inventory = StaticSemanticInventory.create(
        **{**inventory.model_dump(mode="python", exclude={"contract", "id"}),
           "facts": [original, second]},
    )
    new_fused = fuse_static_semantic_and_program_structure(
        project_static_semantic_inventory(new_inventory), fused.source_structure_inventory_snapshot,
    )
    pattern = StaticTriggerPattern.create(
        architecture="arm", instruction_set="aarch64", pattern_name="owned_b1_same_address",
        source_reference_ids=["owned-b1-source"], hardware_reference_ids=["owned-b1-hardware"],
        cases=[StaticTriggerCase.create(case_reference_id="owned-b1-same-address", positions=[
            StaticTriggerPosition.create(position_index=1, alternatives=[
                StaticTriggerPredicate.create(operation="system_register_read"),
                StaticTriggerPredicate.create(operation="system_register_write"),
            ]),
        ])],
    )
    source = _requirements_for_pattern(new_fused, pattern)
    trace = _trace(source, [("0x400000", 0)], run_id="owned-r1-same-address")
    p = bind_candidate_runtime_evidence(source, [trace]).projection
    reqs = source.projection.candidate_requirements
    assert len(reqs) == 2
    assert len(p.instruction_evidence) == 1
    atom = p.instruction_evidence[0]
    assert atom.source_runtime_observation_id == trace.observations[0].id
    assert atom.source_position_candidate_ids == sorted({v for r in reqs for v in r.subject_position_candidate_ids})
    assert atom.source_fused_fact_node_ids == sorted({v for r in reqs for v in r.subject_fused_fact_node_ids})
    assert len(atom.source_position_candidate_ids) == len(atom.source_fused_fact_node_ids) == 2
    assert len(p.requirement_evidence_bindings) == 2
    assert {b.source_runtime_evidence_id for b in p.requirement_evidence_bindings} == {atom.id}


def test_reverse_order_has_ancillary_bindings_and_two_path_gaps(requirements) -> None:
    trace = _trace(requirements, [("0x400008", 0), ("0x400000", 0)], run_id="owned-r1-reverse")
    p = bind_candidate_runtime_evidence(requirements, [trace]).projection
    assert (len(p.instruction_evidence), len(p.order_evidence), len(p.requirement_evidence_bindings), len(p.evidence_gaps)) == (2, 0, 6, 2)
    path_ids = {r.id for r in requirements.projection.candidate_requirements if r.evidence_requirement_kind is StaticCrossLayerEvidenceRequirementKind.PATH_FEASIBILITY_EVIDENCE_REQUIRED}
    assert {g.source_requirement_id for g in p.evidence_gaps} == path_ids
    assert all(g.reason is CandidateRuntimeEvidenceGapReason.NO_MATCHING_RUNTIME_ORDER_OBSERVATION for g in p.evidence_gaps)
    assert path_ids <= {b.source_requirement_id for b in p.requirement_evidence_bindings}
    assert "requirements_with_any_runtime_evidence_count:4" in p.diagnostic_codes
    assert "requirements_without_any_runtime_evidence_count:0" in p.diagnostic_codes
    assert "path_requirements_without_runtime_order_evidence_count:2" in p.diagnostic_codes
    assert "runtime_requirements_without_instruction_evidence_count:0" in p.diagnostic_codes
    assert CandidateRuntimeEvidenceProjection.model_validate(p.model_dump(mode="json")) == p
    values = p.model_dump(mode="python", exclude={"contract", "id", "diagnostic_codes"})
    values["evidence_gaps"] = []
    with pytest.raises(ValidationError, match="requirement-kind-specific"):
        CandidateRuntimeEvidenceProjection.create(**values)


@pytest.mark.parametrize("compatible", [True, False])
def test_empty_trace_kind_specific_gaps_and_capability_precedence(compatible) -> None:
    ns = runpy.run_path(str(ROOT / "tests/test_cross_layer_verification_requirements.py"))
    source = project_cross_layer_verification_requirements(ns["_all_obligation_source"](
        ns["build_public_a77_static_cross_layer_materialization"]()
    ))
    trace = _trace(source, [], run_id="owned-r1-empty", artifact_sha256=None if compatible else "f" * 64)
    p = bind_candidate_runtime_evidence(source, [trace]).projection
    assert not p.requirement_evidence_bindings
    assert len(p.evidence_gaps) == 6
    expected = {
        StaticCrossLayerEvidenceRequirementKind.RUNTIME_EXECUTION_TRACE_REQUIRED:
            CandidateRuntimeEvidenceGapReason.NO_MATCHING_INSTRUCTION_OBSERVATION,
        StaticCrossLayerEvidenceRequirementKind.PATH_FEASIBILITY_EVIDENCE_REQUIRED:
            CandidateRuntimeEvidenceGapReason.NO_MATCHING_RUNTIME_ORDER_OBSERVATION,
    }
    for gap in p.evidence_gaps:
        if gap.source_requirement_kind not in expected:
            assert gap.reason is CandidateRuntimeEvidenceGapReason.CURRENT_RUNTIME_CONTRACT_DOES_NOT_OBSERVE_REQUIREMENT_KIND
        else:
            assert gap.reason == (expected[gap.source_requirement_kind] if compatible else CandidateRuntimeEvidenceGapReason.NO_COMPATIBLE_RUNTIME_TRACE)
    assert len(p.out_of_scope_requirement_ids) == 3


def test_single_incompatibility_contains_all_mismatches(requirements) -> None:
    trace = _trace(requirements, [], run_id="owned-r1-multimismatch", architecture="risc_v", artifact_id="owned-other", artifact_sha256="f" * 64)
    p = bind_candidate_runtime_evidence(requirements, [trace]).projection
    assert len(p.incompatible_runtime_sources) == 1
    assert [r.value for r in p.incompatible_runtime_sources[0].reasons] == [
        "architecture_mismatch", "artifact_id_mismatch", "artifact_sha256_mismatch",
    ]


def test_incompatibility_trace_key_rejects_two_individually_valid_records(requirements) -> None:
    trace = _trace(requirements, [], run_id="owned-r1-duplicate-incompat", artifact_sha256="f" * 64)
    p = bind_candidate_runtime_evidence(requirements, [trace]).projection
    original = p.incompatible_runtime_sources[0]
    other = CandidateRuntimeTraceIncompatibility.create(
        **{**original.model_dump(mode="python", exclude={"contract", "id"}), "reasons": ["architecture_mismatch"]}
    )
    payload = p.model_dump(mode="json")
    payload["incompatible_runtime_sources"].append(other.model_dump(mode="json"))
    from chipchain.verification.candidate_runtime_evidence_models import candidate_runtime_evidence_projection_id
    payload["id"] = candidate_runtime_evidence_projection_id({k: v for k, v in payload.items() if k != "id"})
    with pytest.raises(ValidationError, match="incompatibility trace IDs must be unique"):
        CandidateRuntimeEvidenceProjection.model_validate(payload)


def test_fully_rehashed_false_incompatibility_rejected(requirements) -> None:
    trace = _trace(requirements, [], run_id="owned-r1-false-incompat", artifact_sha256="f" * 64)
    m = bind_candidate_runtime_evidence(requirements, [trace])
    original = m.projection.incompatible_runtime_sources[0]
    other = CandidateRuntimeTraceIncompatibility.create(
        **{**original.model_dump(mode="python", exclude={"contract", "id"}), "reasons": ["architecture_mismatch"]}
    )
    payload = m.projection.model_dump(mode="python")
    payload["incompatible_runtime_sources"] = [other]
    p = _rebuild_projection(payload)
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        CandidateRuntimeEvidenceMaterialization.model_validate(_outer_payload(m, p))


@pytest.mark.parametrize("collection, field", [
    ("instruction_evidence", "observation_vcpu_index"), ("order_evidence", "vcpu_index")
])
def test_fully_rehashed_stored_vcpu_is_source_bound(owned, collection, field) -> None:
    atom = getattr(owned.projection, collection)[0].model_dump(mode="json")
    atom[field] = 1
    (_rehash_instruction if collection == "instruction_evidence" else _rehash_order)(atom)
    p = _replace_evidence_and_bindings(owned, collection=collection, index=0, updated_evidence=atom)
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        CandidateRuntimeEvidenceMaterialization.model_validate(_outer_payload(owned, p))


def test_fully_rehashed_syntactic_foreign_requirement_rejected(owned) -> None:
    values = owned.projection.model_dump(mode="json")
    binding = next(b for b in values["requirement_evidence_bindings"] if b["source_requirement_kind"] == "runtime_execution_trace_required")
    binding["source_requirement_id"] = "static-candidate-verification-requirement:" + "e" * 64
    _rehash_binding(binding)
    p = _rebuild_projection(values)
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        CandidateRuntimeEvidenceMaterialization.model_validate(_outer_payload(owned, p))


def test_valid_compatible_trace_replacement_rejected(owned, requirements) -> None:
    trace = _trace(requirements, [("0x400000", 0)], run_id="owned-r1-replacement")
    assert RuntimeTrace.model_validate(trace.model_dump(mode="json")) == trace
    payload = _outer_payload(owned, owned.projection)
    payload["source_runtime_trace_snapshots"] = [trace.model_dump(mode="json")]
    payload["id"] = candidate_runtime_evidence_materialization_id({k: v for k, v in payload.items() if k != "id"})
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        CandidateRuntimeEvidenceMaterialization.model_validate(payload)


def test_nested_observation_id_tamper_fails_frozen_validation(owned) -> None:
    payload = owned.model_dump(mode="json")
    payload["source_runtime_trace_snapshots"][0]["observations"][0]["id"] = "runtime-observation:" + "f" * 64
    payload["id"] = candidate_runtime_evidence_materialization_id({k: v for k, v in payload.items() if k != "id"})
    with pytest.raises(ValidationError, match="RuntimeObservation ID is not deterministic"):
        CandidateRuntimeEvidenceMaterialization.model_validate(payload)


def test_all_caller_mutations_preserve_full_retained_dump(requirements, owned_trace) -> None:
    source = type(requirements).model_validate(requirements.model_dump(mode="json"))
    trace = RuntimeTrace.model_validate(owned_trace.model_dump(mode="json"))
    traces = [trace]
    result = bind_candidate_runtime_evidence(source, traces)
    before = result.model_dump(mode="json")
    traces.clear()
    trace.observations[0].metadata["owned_caller_mutation"] = True
    trace.observations.clear()
    source.projection.candidate_requirements.clear()
    assert result.model_dump(mode="json") == before
    atom = result.projection.instruction_evidence[0]
    values = atom.model_dump(mode="python", exclude={"contract", "id"})
    detached_atom = CandidateRuntimeInstructionEvidence.create(**values)
    values["source_position_candidate_ids"].clear()
    values["source_fused_fact_node_ids"].clear()
    assert detached_atom == atom
    projection_values = result.projection.model_dump(mode="python", exclude={"contract", "id", "diagnostic_codes"})
    detached_projection = CandidateRuntimeEvidenceProjection.create(**projection_values)
    projection_values["instruction_evidence"].clear()
    projection_values["requirement_evidence_bindings"].clear()
    assert detached_projection == result.projection
    assert result.model_dump(mode="json") == before


def test_exact_instruction_and_order_sets_per_requirement(owned, requirements) -> None:
    source = requirements.source_cross_layer_candidate_materialization_snapshot.source_candidate_materialization_snapshot
    candidates = {c.id: c for c in source.projection.case_candidates}
    facts = {f.id: f for f in source.source_fused_graph_materialization_snapshot.source_semantic_graph_materialization.source_inventory_snapshot.facts}
    catalog = {e.id: e for e in [*owned.projection.instruction_evidence, *owned.projection.order_evidence]}
    for req in requirements.projection.candidate_requirements:
        candidate = candidates[req.source_case_candidate_id]
        positions = {p.id: p for p in candidate.position_candidates}
        addresses = {facts[positions[p].source_semantic_fact_ids[0]].instruction_address for p in req.subject_position_candidate_ids}
        bound = [catalog[b.source_runtime_evidence_id] for b in owned.projection.requirement_evidence_bindings if b.source_requirement_id == req.id]
        expected_observations = {o.id for t in owned.source_runtime_trace_snapshots for o in t.observations if o.event_kind is RuntimeEventKind.INSTRUCTION_EXEC and o.pc and o.pc.value in addresses}
        assert {e.source_runtime_observation_id for e in bound if isinstance(e, CandidateRuntimeInstructionEvidence)} == expected_observations
        if req.evidence_requirement_kind is not StaticCrossLayerEvidenceRequirementKind.PATH_FEASIBILITY_EVIDENCE_REQUIRED:
            continue
        expected_pairs = set()
        for witness in candidate.order_witnesses:
            if witness.id not in req.subject_order_witness_ids:
                continue
            start = facts[positions[witness.source_position_candidate_id].source_semantic_fact_ids[0]].instruction_address
            end = facts[positions[witness.target_position_candidate_id].source_semantic_fact_ids[0]].instruction_address
            for trace in owned.source_runtime_trace_snapshots:
                for a in trace.observations:
                    for b in trace.observations:
                        if (a.event_kind is RuntimeEventKind.INSTRUCTION_EXEC and b.event_kind is RuntimeEventKind.INSTRUCTION_EXEC
                            and a.pc and b.pc and a.pc.value == start and b.pc.value == end
                            and a.vcpu_index == b.vcpu_index and a.sequence_index < b.sequence_index):
                            expected_pairs.add((witness.id, trace.manifest.id, a.id, b.id))
        actual = [e for e in bound if isinstance(e, CandidateRuntimeOrderEvidence)]
        assert {(e.source_static_order_witness_id, e.source_runtime_trace_id, e.source_runtime_observation_id, e.target_runtime_observation_id) for e in actual} == expected_pairs
        expected_ids = {e.id for e in owned.projection.order_evidence if (e.source_static_order_witness_id, e.source_runtime_trace_id, e.source_runtime_observation_id, e.target_runtime_observation_id) in expected_pairs}
        assert {e.id for e in actual} == expected_ids
