"""Authoritative source-reprojection tests for Phase 10D B2-B binding."""

from __future__ import annotations

import copy
from pathlib import Path
import runpy

from pydantic import ValidationError
import pytest

from chipchain.analysis import (
    StaticHardwareReferenceCatalog,
    StaticSemanticInstructionFact,
    StaticSemanticInventory,
    StaticTriggerCase,
    StaticTriggerObjectiveRequirement,
    StaticTriggerPattern,
    StaticTriggerPatternCatalog,
    StaticTriggerPosition,
    StaticTriggerPredicate,
    bind_static_trigger_candidates_to_hardware_references,
    fuse_static_semantic_and_program_structure,
    project_static_semantic_inventory,
    project_static_trigger_candidates,
)
from chipchain.verification import (
    CandidateEffectiveMemoryTypeObservation as Memory,
    CandidateExecutionContextObservation as Context,
    CandidateStateObservationFamily,
    CandidateStateObservationMaterialization as StateMaterialization,
    CandidateStateObservationSourceManifest as StateManifest,
    CandidateStateRequirementAcquisitionGap,
    CandidateStateRequirementAcquisitionGapReason,
    CandidateStateRequirementBindingMaterialization as BindingMaterialization,
    CandidateStateRequirementBindingProjection,
    CandidateStateRequirementObservationBinding,
    CandidateStateSourceIncompatibility,
    CandidateStateSourceIncompatibilityReason,
    StaticCrossLayerEvidenceRequirementKind,
    bind_candidate_state_observations_to_requirements,
    candidate_state_requirement_binding_materialization_id,
    candidate_state_requirement_binding_projection_id,
    candidate_state_requirement_observation_binding_id,
    candidate_state_source_incompatibility_id,
    project_cross_layer_verification_requirements,
)


ROOT = Path(__file__).resolve().parents[1]
RUNNER = runpy.run_path(
    str(ROOT / "scripts/export_candidate_state_requirement_bindings.py"),
    run_name="phase10d_b2b_binding_runner",
)


@pytest.fixture(scope="module")
def requirements():
    return RUNNER["build_owned_b2b_requirement_materialization"]()


@pytest.fixture(scope="module")
def state_source():
    return RUNNER["build_owned_b2b_state_observation_materialization"]()


@pytest.fixture(scope="module")
def result(requirements, state_source):
    return bind_candidate_state_observations_to_requirements(
        requirements, [state_source]
    )


def _values(value):
    return value.model_dump(mode="python", exclude={"contract", "id"})


def _rebuild_state(
    source,
    *,
    manifest_overrides=None,
    memories=None,
    contexts=None,
):
    manifest = StateManifest.create(
        **{
            **_values(source.source_manifest_snapshot),
            **(manifest_overrides or {}),
        }
    )
    common = {
        key: getattr(manifest, key)
        for key in (
            "architecture",
            "artifact_id",
            "artifact_sha256",
            "instruction_set",
        )
    }
    common["source_manifest_id"] = manifest.id
    memory_sources = (
        source.effective_memory_type_observations
        if memories is None
        else memories
    )
    context_sources = (
        source.execution_context_observations if contexts is None else contexts
    )
    return StateMaterialization.create(
        source_manifest_snapshot=manifest,
        effective_memory_type_observations=[
            Memory.create(**{**_values(item), **common}) for item in memory_sources
        ],
        execution_context_observations=[
            Context.create(**{**_values(item), **common}) for item in context_sources
        ],
    )


def _rehash_binding_payload(payload: dict) -> None:
    payload["matched_subject_position_candidate_ids"].sort()
    payload["matched_subject_fused_fact_node_ids"].sort()
    payload["id"] = candidate_state_requirement_observation_binding_id(
        {key: value for key, value in payload.items() if key != "id"}
    )


def _rehash_incompatibility_payload(payload: dict) -> None:
    payload["id"] = candidate_state_source_incompatibility_id(
        {key: value for key, value in payload.items() if key != "id"}
    )


def _rehash_materialization_payload(payload: dict) -> None:
    projection = payload["projection"]
    projection["observation_requirement_bindings"].sort(
        key=lambda item: (
            item["source_requirement_id"],
            item["source_state_observation_id"],
            item["id"],
        )
    )
    projection["acquisition_gaps"].sort(
        key=lambda item: item["source_requirement_id"]
    )
    projection["id"] = candidate_state_requirement_binding_projection_id(
        {key: value for key, value in projection.items() if key != "id"}
    )
    payload["id"] = candidate_state_requirement_binding_materialization_id(
        {key: value for key, value in payload.items() if key != "id"}
    )


def _rebuild_projection_and_materialization_ids(payload: dict) -> None:
    projection = payload["projection"]
    rebuilt = CandidateStateRequirementBindingProjection.create(
        **{
            key: value
            for key, value in projection.items()
            if key not in {"contract", "id", "diagnostic_codes"}
        }
    )
    payload["projection"] = rebuilt.model_dump(mode="json")
    payload["id"] = candidate_state_requirement_binding_materialization_id(
        {key: value for key, value in payload.items() if key != "id"}
    )


def _observation(result, binding):
    return next(
        item
        for source in result.source_state_observation_materialization_snapshots
        for item in [
            *source.effective_memory_type_observations,
            *source.execution_context_observations,
        ]
        if item.id == binding.source_state_observation_id
    )


def _requirement(result, binding):
    return next(
        item
        for item in (
            result.source_requirement_materialization_snapshot.projection
            .candidate_requirements
        )
        if item.id == binding.source_requirement_id
    )


def test_exact_memory_and_context_bindings_are_location_only(result) -> None:
    projection = result.projection
    assert len(projection.observation_requirement_bindings) == 2
    assert projection.acquisition_gaps == []
    assert len(projection.out_of_scope_requirement_ids) == 4
    assert {
        item.source_observation_family
        for item in projection.observation_requirement_bindings
    } == {
        CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE,
        CandidateStateObservationFamily.EXECUTION_CONTEXT,
    }
    for binding in projection.observation_requirement_bindings:
        observation = _observation(result, binding)
        requirement = _requirement(result, binding)
        assert observation.instruction_address.value in {
            subject.instruction_address
            for subject in RUNNER_SOURCE_SUBJECTS(result, requirement)
        }
        assert binding.matched_subject_position_candidate_ids
        assert binding.matched_subject_fused_fact_node_ids


def RUNNER_SOURCE_SUBJECTS(result, requirement):
    candidate_source = (
        result.source_requirement_materialization_snapshot
        .source_cross_layer_candidate_materialization_snapshot
        .source_candidate_materialization_snapshot
    )
    candidate = next(
        item
        for item in candidate_source.projection.case_candidates
        if item.id == requirement.source_case_candidate_id
    )
    return [
        item
        for item in candidate.position_candidates
        if item.id in requirement.subject_position_candidate_ids
    ]


def test_memory_and_context_value_differences_remain_relevant(result) -> None:
    pattern = (
        result.source_requirement_materialization_snapshot
        .source_cross_layer_candidate_materialization_snapshot
        .source_candidate_materialization_snapshot.source_pattern_catalog_snapshot
        .patterns[0]
    )
    required_memory = {
        value
        for case in pattern.cases
        for position in case.positions
        for predicate in position.alternatives
        for value in predicate.required_effective_memory_types
    }
    required_context = {
        value
        for case in pattern.cases
        for position in case.positions
        for predicate in position.alternatives
        for value in predicate.required_execution_contexts
    }
    memory_binding = next(
        item
        for item in result.projection.observation_requirement_bindings
        if item.source_observation_family
        is CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE
    )
    context_binding = next(
        item
        for item in result.projection.observation_requirement_bindings
        if item.source_observation_family
        is CandidateStateObservationFamily.EXECUTION_CONTEXT
    )
    memory = _observation(result, memory_binding)
    context = _observation(result, context_binding)
    assert isinstance(memory, Memory)
    assert isinstance(context, Context)
    assert memory.observed_effective_memory_type_id not in required_memory
    assert set(context.observed_execution_context_ids).isdisjoint(required_context)
    assert not {
        "status",
        "satisfied",
        "value_matches_requirement",
        "conflict",
    } & set(type(memory_binding).model_fields)


def test_wrong_family_bindings_fail_closed(result) -> None:
    for binding in result.projection.observation_requirement_bindings:
        values = _values(binding)
        if binding.source_observation_family is (
            CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE
        ):
            values["source_requirement_kind"] = (
                StaticCrossLayerEvidenceRequirementKind
                .EXECUTION_CONTEXT_EVIDENCE_REQUIRED
            )
        else:
            values["source_requirement_kind"] = (
                StaticCrossLayerEvidenceRequirementKind
                .EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED
            )
        with pytest.raises(ValidationError, match="family/requirement kind"):
            CandidateStateRequirementObservationBinding.create(**values)


def test_no_source_and_unrelated_locations_produce_neutral_gaps(
    requirements, state_source
) -> None:
    absent = bind_candidate_state_observations_to_requirements(requirements, [])
    assert len(absent.projection.acquisition_gaps) == 2
    assert {
        item.reason for item in absent.projection.acquisition_gaps
    } == {
        CandidateStateRequirementAcquisitionGapReason.NO_COMPATIBLE_STATE_SOURCE
    }
    unrelated = StateMaterialization.create(
        source_manifest_snapshot=state_source.source_manifest_snapshot,
        effective_memory_type_observations=[
            state_source.effective_memory_type_observations[1]
        ],
        execution_context_observations=[],
    )
    projected = bind_candidate_state_observations_to_requirements(
        requirements, [unrelated]
    ).projection
    assert projected.observation_requirement_bindings == []
    assert {item.reason for item in projected.acquisition_gaps} == {
        CandidateStateRequirementAcquisitionGapReason
        .NO_EFFECTIVE_MEMORY_TYPE_OBSERVATION_AT_SUBJECT,
        CandidateStateRequirementAcquisitionGapReason
        .NO_EXECUTION_CONTEXT_OBSERVATION_AT_SUBJECT,
    }


def test_complete_incompatibility_and_same_numeric_address_do_not_bind(
    requirements, state_source
) -> None:
    foreign = _rebuild_state(
        state_source,
        manifest_overrides={
            "architecture": "risc_v",
            "artifact_id": "owned-synthetic-foreign-program",
            "artifact_sha256": "b" * 64,
            "instruction_set": "rv64gc",
            "producer_profile_id": "owned-synthetic-foreign-producer",
        },
    )
    projection = bind_candidate_state_observations_to_requirements(
        requirements, [foreign]
    ).projection
    assert projection.observation_requirement_bindings == []
    assert len(projection.incompatible_state_sources) == 1
    assert set(projection.incompatible_state_sources[0].reasons) == set(
        CandidateStateSourceIncompatibilityReason
    )
    assert all(
        item.reason
        is CandidateStateRequirementAcquisitionGapReason.NO_COMPATIBLE_STATE_SOURCE
        for item in projection.acquisition_gaps
    )
    assert foreign.effective_memory_type_observations[0].instruction_address.value == "0x500000"


def test_duplicate_materialization_and_same_manifest_ambiguity_rejected(
    requirements, state_source
) -> None:
    with pytest.raises(ValueError, match="materialization IDs must be unique"):
        bind_candidate_state_observations_to_requirements(
            requirements, [state_source, state_source]
        )
    original = state_source.effective_memory_type_observations[0]
    changed = Memory.create(
        **{
            **_values(original),
            "observed_effective_memory_type_id": "owned-synthetic-other-memory",
        }
    )
    changed_source = StateMaterialization.create(
        source_manifest_snapshot=state_source.source_manifest_snapshot,
        effective_memory_type_observations=[
            changed,
            state_source.effective_memory_type_observations[1],
        ],
        execution_context_observations=(
            state_source.execution_context_observations
        ),
    )
    assert changed_source.id != state_source.id
    with pytest.raises(ValueError, match="competing materializations"):
        bind_candidate_state_observations_to_requirements(
            requirements, [state_source, changed_source]
        )


def test_multiple_compatible_producers_are_retained_and_order_independent(
    requirements, state_source, result
) -> None:
    second = _rebuild_state(
        state_source,
        manifest_overrides={
            "producer_profile_id": "owned-synthetic-b2b-second-producer",
            "source_artifact_id": "owned-synthetic-b2b-second-source",
            "source_artifact_sha256": "c" * 64,
        },
    )
    first_order = bind_candidate_state_observations_to_requirements(
        requirements, [state_source, second]
    )
    reverse_order = bind_candidate_state_observations_to_requirements(
        requirements, [second, state_source]
    )
    assert first_order == reverse_order
    assert len(first_order.projection.observation_requirement_bindings) == 4
    assert set(first_order.projection.compatible_state_materialization_ids) == {
        state_source.id,
        second.id,
    }
    assert len(
        {
            item.source_state_manifest_id
            for item in first_order.projection.observation_requirement_bindings
        }
    ) == 2
    assert first_order.id != result.id


def test_access_address_is_not_binding_authority(
    requirements, state_source
) -> None:
    original = state_source.effective_memory_type_observations[0]
    second_memory = Memory.create(
        **{
            **_values(original),
            "source_record_locator": "record:memory-different-access-address",
            "access_address": {"value": "0x81000000"},
        }
    )
    source = StateMaterialization.create(
        source_manifest_snapshot=state_source.source_manifest_snapshot,
        effective_memory_type_observations=[original, second_memory],
        execution_context_observations=(
            state_source.execution_context_observations
        ),
    )

    projection = bind_candidate_state_observations_to_requirements(
        requirements, [source]
    ).projection
    memory_bindings = [
        item
        for item in projection.observation_requirement_bindings
        if item.source_observation_family
        is CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE
    ]
    assert len(memory_bindings) == 2
    assert {
        item.source_state_observation_id for item in memory_bindings
    } == {original.id, second_memory.id}
    assert projection.acquisition_gaps == []
    assert not {"winner", "rank", "preference", "arbitration"}.intersection(
        CandidateStateRequirementBindingProjection.model_fields
    )


def test_resolution_basis_is_not_binding_authority(
    requirements, state_source
) -> None:
    direct = state_source.effective_memory_type_observations[0]
    audited = Memory.create(
        **{
            **_values(direct),
            "source_record_locator": "record:memory-audited-resolution",
            "resolution_basis": "audited_translation_resolution",
        }
    )
    source = StateMaterialization.create(
        source_manifest_snapshot=state_source.source_manifest_snapshot,
        effective_memory_type_observations=[direct, audited],
        execution_context_observations=(
            state_source.execution_context_observations
        ),
    )

    projection = bind_candidate_state_observations_to_requirements(
        requirements, [source]
    ).projection
    memory_bindings = [
        item
        for item in projection.observation_requirement_bindings
        if item.source_observation_family
        is CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE
    ]
    assert len(memory_bindings) == 2
    assert {
        item.source_state_observation_id for item in memory_bindings
    } == {direct.id, audited.id}
    assert projection.acquisition_gaps == []
    assert not {"winner", "rank", "preference", "evaluation"}.intersection(
        CandidateStateRequirementBindingProjection.model_fields
    )


def test_conflicting_producer_claims_are_all_retained_without_decision(
    requirements, state_source
) -> None:
    source_a = StateMaterialization.create(
        source_manifest_snapshot=state_source.source_manifest_snapshot,
        effective_memory_type_observations=[
            state_source.effective_memory_type_observations[0]
        ],
        execution_context_observations=(
            state_source.execution_context_observations
        ),
    )
    memory_b = Memory.create(
        **{
            **_values(source_a.effective_memory_type_observations[0]),
            "observed_effective_memory_type_id": (
                "owned-synthetic-conflicting-memory"
            ),
        }
    )
    context_b = Context.create(
        **{
            **_values(source_a.execution_context_observations[0]),
            "observed_execution_context_ids": [
                "owned-synthetic-disjoint-context"
            ],
        }
    )
    source_b = _rebuild_state(
        source_a,
        manifest_overrides={
            "producer_profile_id": "owned-synthetic-conflicting-producer",
            "source_artifact_id": "owned-synthetic-conflicting-source",
            "source_artifact_sha256": "d" * 64,
        },
        memories=[memory_b],
        contexts=[context_b],
    )

    projection = bind_candidate_state_observations_to_requirements(
        requirements, [source_a, source_b]
    ).projection
    assert projection.acquisition_gaps == []
    assert len(projection.observation_requirement_bindings) == 4
    for family in CandidateStateObservationFamily:
        family_bindings = [
            item
            for item in projection.observation_requirement_bindings
            if item.source_observation_family is family
        ]
        assert len(family_bindings) == 2
        assert len(
            {item.source_state_manifest_id for item in family_bindings}
        ) == 2
    forbidden = {
        "winner",
        "majority",
        "confidence",
        "conflict",
        "satisfied",
        "status",
    }
    assert forbidden.isdisjoint(type(projection).model_fields)
    assert all(
        forbidden.isdisjoint(type(item).model_fields)
        for item in projection.observation_requirement_bindings
    )


def test_mixed_compatible_and_incompatible_sources_are_order_independent(
    requirements, state_source
) -> None:
    incompatible = _rebuild_state(
        state_source,
        manifest_overrides={
            "artifact_id": "owned-synthetic-incompatible-artifact"
        },
    )
    forward = bind_candidate_state_observations_to_requirements(
        requirements, [state_source, incompatible]
    )
    reverse = bind_candidate_state_observations_to_requirements(
        requirements, [incompatible, state_source]
    )

    assert forward == reverse
    assert len(forward.projection.observation_requirement_bindings) == 2
    assert forward.projection.acquisition_gaps == []
    assert len(forward.projection.incompatible_state_sources) == 1
    assert forward.projection.incompatible_state_sources[0].reasons == [
        CandidateStateSourceIncompatibilityReason.ARTIFACT_ID_MISMATCH
    ]


def test_option_a_changed_value_remains_binding_without_verdict(
    requirements, state_source, result
) -> None:
    original = state_source.effective_memory_type_observations[0]
    changed_observation = Memory.create(
        **{
            **_values(original),
            "observed_effective_memory_type_id": "owned-synthetic-option-a-change",
        }
    )
    changed_source = StateMaterialization.create(
        source_manifest_snapshot=state_source.source_manifest_snapshot,
        effective_memory_type_observations=[
            changed_observation,
            state_source.effective_memory_type_observations[1],
        ],
        execution_context_observations=(
            state_source.execution_context_observations
        ),
    )
    changed = bind_candidate_state_observations_to_requirements(
        requirements, [changed_source]
    )
    original_memory_binding = next(
        item
        for item in result.projection.observation_requirement_bindings
        if item.source_observation_family
        is CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE
    )
    changed_memory_binding = next(
        item
        for item in changed.projection.observation_requirement_bindings
        if item.source_observation_family
        is CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE
    )
    assert changed_memory_binding.id != original_memory_binding.id
    assert changed.projection.acquisition_gaps == []


def test_context_option_a_changed_value_remains_fresh_binding_without_verdict(
    requirements, state_source, result
) -> None:
    original = state_source.execution_context_observations[0]
    changed_observation = Context.create(
        **{
            **_values(original),
            "observed_execution_context_ids": [
                "owned-synthetic-option-a-context"
            ],
        }
    )
    changed_source = StateMaterialization.create(
        source_manifest_snapshot=state_source.source_manifest_snapshot,
        effective_memory_type_observations=(
            state_source.effective_memory_type_observations
        ),
        execution_context_observations=[changed_observation],
    )
    changed = bind_candidate_state_observations_to_requirements(
        requirements, [changed_source]
    )
    original_binding = next(
        item
        for item in result.projection.observation_requirement_bindings
        if item.source_observation_family
        is CandidateStateObservationFamily.EXECUTION_CONTEXT
    )
    changed_binding = next(
        item
        for item in changed.projection.observation_requirement_bindings
        if item.source_observation_family
        is CandidateStateObservationFamily.EXECUTION_CONTEXT
    )
    assert changed_observation.instruction_address == original.instruction_address
    assert changed_observation.id != original.id
    assert changed_binding.id != original_binding.id
    assert changed.projection.acquisition_gaps == []
    assert not {"status", "satisfied", "verdict"}.intersection(
        type(changed_binding).model_fields
    )


def test_equal_and_different_values_have_identical_structural_relevance(
    requirements, state_source
) -> None:
    different_source = StateMaterialization.create(
        source_manifest_snapshot=state_source.source_manifest_snapshot,
        effective_memory_type_observations=[
            state_source.effective_memory_type_observations[0]
        ],
        execution_context_observations=[
            state_source.execution_context_observations[0]
        ],
    )
    different_result = bind_candidate_state_observations_to_requirements(
        requirements, [different_source]
    )
    equal_memory = Memory.create(
        **{
            **_values(state_source.effective_memory_type_observations[0]),
            "observed_effective_memory_type_id": "owned-synthetic-normal-memory",
        }
    )
    equal_context = Context.create(
        **{
            **_values(state_source.execution_context_observations[0]),
            "observed_execution_context_ids": ["owned-synthetic-el1"],
        }
    )
    equal_source = StateMaterialization.create(
        source_manifest_snapshot=state_source.source_manifest_snapshot,
        effective_memory_type_observations=[equal_memory],
        execution_context_observations=[equal_context],
    )
    equal_result = bind_candidate_state_observations_to_requirements(
        requirements, [equal_source]
    )

    assert different_result.projection.acquisition_gaps == []
    assert equal_result.projection.acquisition_gaps == []
    assert {
        item.source_observation_family
        for item in different_result.projection.observation_requirement_bindings
    } == {
        item.source_observation_family
        for item in equal_result.projection.observation_requirement_bindings
    } == set(CandidateStateObservationFamily)
    assert len(
        different_result.projection.observation_requirement_bindings
    ) == len(equal_result.projection.observation_requirement_bindings) == 2
    assert different_result.id != equal_result.id
    forbidden = {
        "match",
        "support",
        "satisfaction",
        "conflict",
        "correctness",
        "value_equal",
    }
    for projection in (different_result.projection, equal_result.projection):
        assert all(
            not any(token in code.lower() for token in forbidden)
            for code in projection.diagnostic_codes
        )
        assert all(
            forbidden.isdisjoint(type(item).model_fields)
            for item in projection.observation_requirement_bindings
        )


def _same_address_requirements(*, include_store_as_subject: bool = True):
    fused = RUNNER["_owned_synthetic_fused_program"]()
    inventory = (
        fused.source_semantic_graph_materialization.source_inventory_snapshot
    )
    load, store = inventory.facts
    store_values = store.model_dump(mode="python", exclude={"contract", "id"})
    store_values["instruction_address"] = "0x500000"
    same_address_store = StaticSemanticInstructionFact.create(**store_values)
    changed_inventory = StaticSemanticInventory.create(
        **{
            **inventory.model_dump(mode="python", exclude={"contract", "id", "facts"}),
            "facts": [load, same_address_store],
        }
    )
    changed_fused = fuse_static_semantic_and_program_structure(
        project_static_semantic_inventory(changed_inventory),
        fused.source_structure_inventory_snapshot,
    )
    subject_predicate_values = {
        "required_effective_memory_types": ["owned-synthetic-normal-memory"],
        "objective_requirements": [
            StaticTriggerObjectiveRequirement
            .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
        ],
    }
    pattern = StaticTriggerPattern.create(
        architecture="arm",
        instruction_set="aarch64",
        pattern_name="owned_synthetic_b2b_same_address",
        source_reference_ids=["owned-synthetic-b2b-same-address-source"],
        hardware_reference_ids=["owned-synthetic-b2b-same-address-hardware"],
        cases=[
            StaticTriggerCase.create(
                case_reference_id="owned-synthetic-b2b-same-address-case",
                positions=[
                    StaticTriggerPosition.create(
                        position_index=1,
                        alternatives=[
                            StaticTriggerPredicate.create(
                                operation="memory_load",
                                **subject_predicate_values,
                            )
                        ],
                    ),
                    StaticTriggerPosition.create(
                        position_index=2,
                        alternatives=[
                            StaticTriggerPredicate.create(
                                operation="memory_store",
                                **(
                                    subject_predicate_values
                                    if include_store_as_subject
                                    else {}
                                ),
                            )
                        ],
                    ),
                ],
            )
        ],
    )
    candidates = project_static_trigger_candidates(
        changed_fused, StaticTriggerPatternCatalog.create(patterns=[pattern])
    )
    cross_layer = bind_static_trigger_candidates_to_hardware_references(
        candidates, StaticHardwareReferenceCatalog.create(references=[])
    )
    return project_cross_layer_verification_requirements(cross_layer)


def test_one_observation_preserves_complete_same_address_subject_union(
    state_source,
) -> None:
    requirements = _same_address_requirements()
    projection = bind_candidate_state_observations_to_requirements(
        requirements,
        [
            StateMaterialization.create(
                source_manifest_snapshot=state_source.source_manifest_snapshot,
                effective_memory_type_observations=[
                    state_source.effective_memory_type_observations[0]
                ],
                execution_context_observations=[],
            )
        ],
    ).projection
    memory_requirement = next(
        item
        for item in requirements.projection.candidate_requirements
        if item.evidence_requirement_kind
        is StaticCrossLayerEvidenceRequirementKind
        .EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED
    )
    assert len(memory_requirement.subject_position_candidate_ids) == 2
    assert len(memory_requirement.subject_fused_fact_node_ids) == 2
    bindings = [
        item
        for item in projection.observation_requirement_bindings
        if item.source_requirement_id == memory_requirement.id
    ]
    assert len(bindings) == 1
    assert bindings[0].matched_subject_position_candidate_ids == (
        memory_requirement.subject_position_candidate_ids
    )
    assert bindings[0].matched_subject_fused_fact_node_ids == (
        memory_requirement.subject_fused_fact_node_ids
    )


def test_same_address_real_non_subject_is_excluded_and_reinjection_rejected(
    state_source,
) -> None:
    requirements = _same_address_requirements(include_store_as_subject=False)
    state = StateMaterialization.create(
        source_manifest_snapshot=state_source.source_manifest_snapshot,
        effective_memory_type_observations=[
            state_source.effective_memory_type_observations[0]
        ],
        execution_context_observations=[],
    )
    result = bind_candidate_state_observations_to_requirements(
        requirements, [state]
    )
    requirement = next(
        item
        for item in requirements.projection.candidate_requirements
        if item.evidence_requirement_kind
        is StaticCrossLayerEvidenceRequirementKind
        .EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED
    )
    candidate_source = (
        requirements.source_cross_layer_candidate_materialization_snapshot
        .source_candidate_materialization_snapshot
    )
    candidate = next(
        item
        for item in candidate_source.projection.case_candidates
        if item.id == requirement.source_case_candidate_id
    )
    foreign_position = next(
        item
        for item in candidate.position_candidates
        if item.id not in requirement.subject_position_candidate_ids
    )
    observation = state.effective_memory_type_observations[0]
    assert foreign_position.instruction_address == observation.instruction_address.value
    binding = result.projection.observation_requirement_bindings[0]
    assert foreign_position.id not in binding.matched_subject_position_candidate_ids
    assert (
        foreign_position.source_fused_fact_node_id
        not in binding.matched_subject_fused_fact_node_ids
    )

    payload = result.model_dump(mode="json")
    forged = payload["projection"]["observation_requirement_bindings"][0]
    forged["matched_subject_position_candidate_ids"].append(
        foreign_position.id
    )
    forged["matched_subject_fused_fact_node_ids"].append(
        foreign_position.source_fused_fact_node_id
    )
    _rehash_binding_payload(forged)
    _rehash_materialization_payload(payload)
    CandidateStateRequirementBindingProjection.model_validate(
        payload["projection"]
    )
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        BindingMaterialization.model_validate(payload)


def _multiple_memory_requirements():
    fused = RUNNER["_owned_synthetic_fused_program"]()
    cases = [
        StaticTriggerCase.create(
            case_reference_id=f"owned-synthetic-b2b-reuse-{index}",
            positions=[
                StaticTriggerPosition.create(
                    position_index=1,
                    alternatives=[
                        StaticTriggerPredicate.create(
                            operation=operation,
                            required_effective_memory_types=[memory_type],
                            objective_requirements=[
                                StaticTriggerObjectiveRequirement
                                .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
                            ],
                        )
                    ],
                )
            ],
        )
        for index, (operation, memory_type) in enumerate(
            [
                ("memory_load", "owned-synthetic-normal-memory"),
                ("memory_load", "owned-synthetic-device-memory"),
                ("memory_store", "owned-synthetic-normal-memory"),
            ],
            1,
        )
    ]
    pattern = StaticTriggerPattern.create(
        architecture="arm",
        instruction_set="aarch64",
        pattern_name="owned_synthetic_b2b_observation_reuse",
        source_reference_ids=["owned-synthetic-b2b-reuse-source"],
        hardware_reference_ids=["owned-synthetic-b2b-reuse-hardware"],
        cases=cases,
    )
    candidates = project_static_trigger_candidates(
        fused, StaticTriggerPatternCatalog.create(patterns=[pattern])
    )
    cross_layer = bind_static_trigger_candidates_to_hardware_references(
        candidates, StaticHardwareReferenceCatalog.create(references=[])
    )
    return project_cross_layer_verification_requirements(cross_layer)


def _single_family_requirements(
    family: CandidateStateObservationFamily,
):
    is_memory = (
        family is CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE
    )
    predicate_values = (
        {
            "required_effective_memory_types": [
                "owned-synthetic-normal-memory"
            ],
            "objective_requirements": [
                StaticTriggerObjectiveRequirement
                .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
            ],
        }
        if is_memory
        else {
            "required_execution_contexts": ["owned-synthetic-el1"],
            "objective_requirements": [
                StaticTriggerObjectiveRequirement
                .RUNTIME_EXECUTION_CONTEXT_REQUIRED
            ],
        }
    )
    operation = "memory_load" if is_memory else "memory_store"
    pattern = StaticTriggerPattern.create(
        architecture="arm",
        instruction_set="aarch64",
        pattern_name=f"owned_synthetic_b2b_{family.value}_only",
        source_reference_ids=[f"owned-synthetic-{family.value}-source"],
        hardware_reference_ids=[f"owned-synthetic-{family.value}-hardware"],
        cases=[
            StaticTriggerCase.create(
                case_reference_id=f"owned-synthetic-{family.value}-case",
                positions=[
                    StaticTriggerPosition.create(
                        position_index=1,
                        alternatives=[
                            StaticTriggerPredicate.create(
                                operation=operation,
                                **predicate_values,
                            )
                        ],
                    )
                ],
            )
        ],
    )
    candidates = project_static_trigger_candidates(
        RUNNER["_owned_synthetic_fused_program"](),
        StaticTriggerPatternCatalog.create(patterns=[pattern]),
    )
    cross_layer = bind_static_trigger_candidates_to_hardware_references(
        candidates, StaticHardwareReferenceCatalog.create(references=[])
    )
    return project_cross_layer_verification_requirements(cross_layer)


@pytest.mark.parametrize(
    ("required_family", "expected_reason"),
    [
        (
            CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE,
            CandidateStateRequirementAcquisitionGapReason
            .NO_EFFECTIVE_MEMORY_TYPE_OBSERVATION_AT_SUBJECT,
        ),
        (
            CandidateStateObservationFamily.EXECUTION_CONTEXT,
            CandidateStateRequirementAcquisitionGapReason
            .NO_EXECUTION_CONTEXT_OBSERVATION_AT_SUBJECT,
        ),
    ],
)
def test_wrong_family_at_exact_subject_produces_family_specific_gap(
    state_source, required_family, expected_reason
) -> None:
    requirements = _single_family_requirements(required_family)
    if required_family is CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE:
        original = state_source.execution_context_observations[0]
        wrong_family = Context.create(
            **{
                **_values(original),
                "instruction_address": "0x500000",
            }
        )
        source = StateMaterialization.create(
            source_manifest_snapshot=state_source.source_manifest_snapshot,
            effective_memory_type_observations=[],
            execution_context_observations=[wrong_family],
        )
    else:
        original = state_source.effective_memory_type_observations[0]
        wrong_family = Memory.create(
            **{
                **_values(original),
                "instruction_address": "0x500004",
            }
        )
        source = StateMaterialization.create(
            source_manifest_snapshot=state_source.source_manifest_snapshot,
            effective_memory_type_observations=[wrong_family],
            execution_context_observations=[],
        )

    projection = bind_candidate_state_observations_to_requirements(
        requirements, [source]
    ).projection
    assert projection.observation_requirement_bindings == []
    assert len(projection.acquisition_gaps) == 1
    assert projection.acquisition_gaps[0].reason is expected_reason
    assert projection.acquisition_gaps[0].reason is not (
        CandidateStateRequirementAcquisitionGapReason
        .NO_COMPATIBLE_STATE_SOURCE
    )


def test_one_observation_can_bind_multiple_requirements(state_source) -> None:
    requirements = _multiple_memory_requirements()
    state = StateMaterialization.create(
        source_manifest_snapshot=state_source.source_manifest_snapshot,
        effective_memory_type_observations=[
            state_source.effective_memory_type_observations[0]
        ],
        execution_context_observations=[],
    )
    projection = bind_candidate_state_observations_to_requirements(
        requirements, [state]
    ).projection
    observation_id = state.effective_memory_type_observations[0].id
    bindings = [
        item
        for item in projection.observation_requirement_bindings
        if item.source_state_observation_id == observation_id
    ]
    assert len(bindings) == 2
    assert len({item.source_requirement_id for item in bindings}) == 2
    assert len(projection.acquisition_gaps) == 1


def test_fully_rehashed_binding_to_valid_wrong_requirement_rejected(
    state_source,
) -> None:
    requirements = _multiple_memory_requirements()
    state = StateMaterialization.create(
        source_manifest_snapshot=state_source.source_manifest_snapshot,
        effective_memory_type_observations=[
            state_source.effective_memory_type_observations[0]
        ],
        execution_context_observations=[],
    )
    result = bind_candidate_state_observations_to_requirements(
        requirements, [state]
    )
    projection = result.projection
    original_binding = projection.observation_requirement_bindings[0]
    wrong_gap = projection.acquisition_gaps[0]
    original_requirement = next(
        item
        for item in requirements.projection.candidate_requirements
        if item.id == original_binding.source_requirement_id
    )
    wrong_requirement = next(
        item
        for item in requirements.projection.candidate_requirements
        if item.id == wrong_gap.source_requirement_id
    )
    original_addresses = {
        item.instruction_address
        for item in RUNNER_SOURCE_SUBJECTS(result, original_requirement)
    }
    wrong_addresses = {
        item.instruction_address
        for item in RUNNER_SOURCE_SUBJECTS(result, wrong_requirement)
    }
    assert original_addresses == {"0x500000"}
    assert wrong_addresses == {"0x500004"}

    payload = result.model_dump(mode="json")
    binding = next(
        item
        for item in payload["projection"]["observation_requirement_bindings"]
        if item["id"] == original_binding.id
    )
    binding["source_requirement_id"] = wrong_requirement.id
    binding["source_requirement_kind"] = wrong_requirement.evidence_requirement_kind.value
    binding["source_case_candidate_id"] = wrong_requirement.source_case_candidate_id
    _rehash_binding_payload(binding)
    replacement_gap = CandidateStateRequirementAcquisitionGap.create(
        source_requirement_materialization_id=requirements.id,
        source_requirement_projection_id=requirements.projection.id,
        source_requirement_id=original_requirement.id,
        source_requirement_kind=original_requirement.evidence_requirement_kind,
        source_case_candidate_id=original_requirement.source_case_candidate_id,
        reason=(
            CandidateStateRequirementAcquisitionGapReason
            .NO_EFFECTIVE_MEMORY_TYPE_OBSERVATION_AT_SUBJECT
        ),
    )
    payload["projection"]["acquisition_gaps"] = [
        replacement_gap.model_dump(mode="json")
    ]
    _rehash_materialization_payload(payload)
    CandidateStateRequirementBindingProjection.model_validate(payload["projection"])
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        BindingMaterialization.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "foreign_value"),
    [
        ("source_state_observation_id", "candidate-state-observation:foreign"),
        ("source_requirement_id", "static-candidate-verification-requirement:foreign"),
        ("matched_subject_position_candidate_ids", ["static-trigger-position-candidate:foreign"]),
        ("matched_subject_fused_fact_node_ids", ["static-fused-behavior-node:foreign"]),
    ],
)
def test_fully_rehashed_foreign_binding_references_rejected(
    result, field, foreign_value
) -> None:
    payload = result.model_dump(mode="json")
    binding = payload["projection"]["observation_requirement_bindings"][0]
    binding[field] = foreign_value
    _rehash_binding_payload(binding)
    _rehash_materialization_payload(payload)
    CandidateStateRequirementBindingProjection.model_validate(payload["projection"])
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        BindingMaterialization.model_validate(payload)


def test_incomplete_same_address_subject_union_rejected(state_source) -> None:
    requirements = _same_address_requirements()
    state = StateMaterialization.create(
        source_manifest_snapshot=state_source.source_manifest_snapshot,
        effective_memory_type_observations=[
            state_source.effective_memory_type_observations[0]
        ],
        execution_context_observations=[],
    )
    result = bind_candidate_state_observations_to_requirements(
        requirements, [state]
    )
    payload = result.model_dump(mode="json")
    binding = next(
        item
        for item in payload["projection"]["observation_requirement_bindings"]
        if item["source_requirement_kind"]
        == "effective_memory_type_evidence_required"
    )
    binding["matched_subject_position_candidate_ids"].pop()
    binding["matched_subject_fused_fact_node_ids"].pop()
    _rehash_binding_payload(binding)
    _rehash_materialization_payload(payload)
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        BindingMaterialization.model_validate(payload)


def test_fully_rehashed_real_but_foreign_subjects_rejected(result) -> None:
    memory_binding = next(
        item
        for item in result.projection.observation_requirement_bindings
        if item.source_observation_family
        is CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE
    )
    requirement = _requirement(result, memory_binding)
    subjects = RUNNER_SOURCE_SUBJECTS(result, requirement)
    matched_positions = set(memory_binding.matched_subject_position_candidate_ids)
    foreign = next(
        item for item in subjects if item.id not in matched_positions
    )
    assert foreign.instruction_address != _observation(
        result, memory_binding
    ).instruction_address.value
    payload = result.model_dump(mode="json")
    binding = next(
        item
        for item in payload["projection"]["observation_requirement_bindings"]
        if item["id"] == memory_binding.id
    )
    binding["matched_subject_position_candidate_ids"] = [foreign.id]
    binding["matched_subject_fused_fact_node_ids"] = [
        foreign.source_fused_fact_node_id
    ]
    _rehash_binding_payload(binding)
    _rehash_materialization_payload(payload)
    CandidateStateRequirementBindingProjection.model_validate(payload["projection"])
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        BindingMaterialization.model_validate(payload)


def test_foreign_state_source_provenance_rejected(
    requirements, state_source
) -> None:
    second = _rebuild_state(
        state_source,
        manifest_overrides={"producer_profile_id": "owned-synthetic-b2b-third"},
    )
    result = bind_candidate_state_observations_to_requirements(
        requirements, [state_source, second]
    )
    payload = result.model_dump(mode="json")
    binding = payload["projection"]["observation_requirement_bindings"][0]
    other = next(
        item
        for item in payload["source_state_observation_materialization_snapshots"]
        if item["id"] != binding["source_state_materialization_id"]
    )
    binding["source_state_materialization_id"] = other["id"]
    binding["source_state_manifest_id"] = other["source_manifest_snapshot"]["id"]
    _rehash_binding_payload(binding)
    _rehash_materialization_payload(payload)
    CandidateStateRequirementBindingProjection.model_validate(payload["projection"])
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        BindingMaterialization.model_validate(payload)


def test_fully_rehashed_false_incompatibility_reason_rejected(
    requirements, state_source
) -> None:
    incompatible = _rebuild_state(
        state_source,
        manifest_overrides={
            "artifact_id": "owned-synthetic-wrong-artifact-only"
        },
    )
    result = bind_candidate_state_observations_to_requirements(
        requirements, [incompatible]
    )
    assert result.projection.incompatible_state_sources[0].reasons == [
        CandidateStateSourceIncompatibilityReason.ARTIFACT_ID_MISMATCH
    ]

    payload = result.model_dump(mode="json")
    forged = payload["projection"]["incompatible_state_sources"][0]
    forged["reasons"] = [
        CandidateStateSourceIncompatibilityReason.ARCHITECTURE_MISMATCH.value
    ]
    _rehash_incompatibility_payload(forged)
    _rehash_materialization_payload(payload)
    CandidateStateRequirementBindingProjection.model_validate(
        payload["projection"]
    )
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        BindingMaterialization.model_validate(payload)


def test_real_observation_cannot_be_forged_into_another_retained_source(
    requirements, state_source
) -> None:
    source_b = _rebuild_state(
        state_source,
        manifest_overrides={
            "producer_profile_id": "owned-synthetic-b2b-source-b",
            "source_artifact_id": "owned-synthetic-b2b-source-b-artifact",
            "source_artifact_sha256": "e" * 64,
        },
    )
    result = bind_candidate_state_observations_to_requirements(
        requirements, [state_source, source_b]
    )
    source_b_observation_ids = {
        item.id
        for item in [
            *source_b.effective_memory_type_observations,
            *source_b.execution_context_observations,
        ]
    }
    payload = result.model_dump(mode="json")
    forged = next(
        item
        for item in payload["projection"]["observation_requirement_bindings"]
        if item["source_state_observation_id"] in source_b_observation_ids
    )
    forged["source_state_materialization_id"] = state_source.id
    forged["source_state_manifest_id"] = (
        state_source.source_manifest_snapshot.id
    )
    _rehash_binding_payload(forged)
    _rehash_materialization_payload(payload)
    CandidateStateRequirementBindingProjection.model_validate(
        payload["projection"]
    )
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        BindingMaterialization.model_validate(payload)


def test_foreign_out_of_scope_requirement_id_rejected(result) -> None:
    payload = result.model_dump(mode="json")
    payload["projection"]["out_of_scope_requirement_ids"].append(
        "static-candidate-verification-requirement:foreign-out-of-scope"
    )
    _rebuild_projection_and_materialization_ids(payload)
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        BindingMaterialization.model_validate(payload)


def test_supported_requirement_forged_as_out_of_scope_rejected(result) -> None:
    payload = result.model_dump(mode="json")
    forged = payload["projection"]["observation_requirement_bindings"].pop()
    payload["projection"]["out_of_scope_requirement_ids"].append(
        forged["source_requirement_id"]
    )
    _rebuild_projection_and_materialization_ids(payload)
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        BindingMaterialization.model_validate(payload)


def test_different_id_duplicate_logical_binding_rejected(result) -> None:
    projection = result.projection
    original = projection.observation_requirement_bindings[0]
    requirement = _requirement(result, original)
    alternative_position_id = next(
        item
        for item in requirement.subject_position_candidate_ids
        if item not in original.matched_subject_position_candidate_ids
    )
    candidate = next(
        item
        for item in (
            result.source_requirement_materialization_snapshot
            .source_cross_layer_candidate_materialization_snapshot
            .source_candidate_materialization_snapshot.projection.case_candidates
        )
        if item.id == requirement.source_case_candidate_id
    )
    alternative_position = next(
        item
        for item in candidate.position_candidates
        if item.id == alternative_position_id
    )
    duplicate = CandidateStateRequirementObservationBinding.create(
        **{
            **_values(original),
            "matched_subject_position_candidate_ids": [alternative_position.id],
            "matched_subject_fused_fact_node_ids": [
                alternative_position.source_fused_fact_node_id
            ],
        }
    )
    assert duplicate.id != original.id
    values = projection.model_dump(
        mode="python", exclude={"contract", "id", "diagnostic_codes"}
    )
    with pytest.raises(ValidationError, match="logically unique"):
        CandidateStateRequirementBindingProjection.create(
            **{
                **values,
                "observation_requirement_bindings": [
                    *projection.observation_requirement_bindings,
                    duplicate,
                ],
            }
        )


def test_duplicate_incompatibility_source_key_rejected(
    requirements, state_source
) -> None:
    incompatible = _rebuild_state(
        state_source,
        manifest_overrides={
            "artifact_id": "owned-synthetic-incompatibility-source"
        },
    )
    projection = bind_candidate_state_observations_to_requirements(
        requirements, [incompatible]
    ).projection
    original = projection.incompatible_state_sources[0]
    duplicate = CandidateStateSourceIncompatibility.create(
        **{
            **_values(original),
            "observed_architecture": "risc_v",
            "reasons": [
                CandidateStateSourceIncompatibilityReason.ARCHITECTURE_MISMATCH
            ],
        }
    )
    assert duplicate.id != original.id
    values = projection.model_dump(
        mode="python", exclude={"contract", "id", "diagnostic_codes"}
    )
    with pytest.raises(ValidationError, match="source-specific"):
        CandidateStateRequirementBindingProjection.create(
            **{
                **values,
                "incompatible_state_sources": [original, duplicate],
            }
        )


def test_source_snapshot_tampering_rejected(requirements, state_source, result) -> None:
    invalid = result.model_dump(mode="json")
    invalid["source_state_observation_materialization_snapshots"][0]["id"] = "stale"
    with pytest.raises(ValidationError, match="state source ID is not deterministic"):
        BindingMaterialization.model_validate(invalid)

    different = _rebuild_state(
        state_source,
        manifest_overrides={"producer_profile_id": "owned-synthetic-b2b-fourth"},
    )
    source_changed = result.model_dump(mode="json")
    source_changed["source_state_observation_materialization_snapshots"] = [
        different.model_dump(mode="json")
    ]
    source_changed["id"] = candidate_state_requirement_binding_materialization_id(
        {
            key: value
            for key, value in source_changed.items()
            if key != "id"
        }
    )
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        BindingMaterialization.model_validate(source_changed)

    other_requirements = _multiple_memory_requirements()
    requirement_changed = result.model_dump(mode="json")
    requirement_changed["source_requirement_materialization_id"] = other_requirements.id
    requirement_changed["source_requirement_materialization_snapshot"] = (
        other_requirements.model_dump(mode="json")
    )
    requirement_changed["id"] = candidate_state_requirement_binding_materialization_id(
        {
            key: value
            for key, value in requirement_changed.items()
            if key != "id"
        }
    )
    with pytest.raises(ValidationError, match="deterministic source reprojection"):
        BindingMaterialization.model_validate(requirement_changed)


def test_caller_mutation_does_not_change_retained_materialization(
    requirements, state_source
) -> None:
    caller_requirements = type(requirements).model_validate(
        requirements.model_dump(mode="json")
    )
    caller_state = StateMaterialization.model_validate(
        state_source.model_dump(mode="json")
    )
    caller_list = [caller_state]
    retained = bind_candidate_state_observations_to_requirements(
        caller_requirements, caller_list
    )
    before = retained.model_dump(mode="json")
    caller_memory = caller_state.effective_memory_type_observations[0]
    caller_context = caller_state.execution_context_observations[0]
    caller_supported_requirement = next(
        item
        for item in caller_requirements.projection.candidate_requirements
        if item.evidence_requirement_kind
        is StaticCrossLayerEvidenceRequirementKind
        .EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED
    )
    caller_supported_requirement.subject_position_candidate_ids.clear()
    caller_supported_requirement.subject_fused_fact_node_ids.clear()
    object.__setattr__(
        caller_memory,
        "observed_effective_memory_type_id",
        "caller-mutated-memory-value",
    )
    object.__setattr__(caller_memory.access_address, "value", "0xdeadbeef")
    caller_context.observed_execution_context_ids.append(
        "caller-mutated-context"
    )
    caller_list.clear()
    caller_state.effective_memory_type_observations.clear()
    caller_state.execution_context_observations.clear()
    object.__setattr__(
        caller_state.source_manifest_snapshot,
        "producer_profile_version",
        "mutated",
    )
    caller_requirements.projection.candidate_requirements.clear()
    assert retained.model_dump(mode="json") == before


def test_owned_diamond_and_public_a77_remain_zero() -> None:
    ordinary = RUNNER[
        "build_owned_diamond_state_requirement_binding_materialization"
    ]()
    assert ordinary.projection.observation_requirement_bindings == []
    assert ordinary.projection.acquisition_gaps == []
    assert len(ordinary.projection.out_of_scope_requirement_ids) == 16
    public = RUNNER["build_public_a77_state_requirement_binding_materialization"]()
    assert public.projection.observation_requirement_bindings == []
    assert public.projection.acquisition_gaps == []
    assert public.projection.out_of_scope_requirement_ids == []


def test_ten_rebuilds_are_identical(result) -> None:
    outputs = [
        RUNNER["build_owned_state_requirement_binding_materialization"]()
        for _ in range(10)
    ]
    assert {item.id for item in outputs} == {result.id}
    assert {item.projection.id for item in outputs} == {result.projection.id}
    assert {item.model_dump_json() for item in outputs} == {
        result.model_dump_json()
    }
