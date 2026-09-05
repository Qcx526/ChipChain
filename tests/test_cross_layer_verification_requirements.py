"""Source-reprojection tests for Phase 10D 2D4-A requirements."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import runpy

from pydantic import ValidationError
import pytest

from chipchain.analysis import (
    StaticProgramCfgEdge,
    StaticProgramCfgSemantics,
    StaticProgramFunctionCfg,
    StaticProgramStructureInventory,
    StaticHardwareReferenceCatalog,
    StaticSemanticFactScope,
    StaticSemanticInstructionFact,
    StaticSemanticInventory,
    StaticSemanticInventoryScope,
    StaticSemanticOperation,
    StaticTriggerCase,
    StaticTriggerPattern,
    StaticTriggerPatternCatalog,
    StaticTriggerPredicate,
    StaticTriggerPosition,
    StaticTriggerRelationEvaluability,
    StaticTriggerRelationKind,
    StaticTriggerRelationPrecision,
    StaticTriggerRelationRequirement,
    StaticTriggerObjectiveRequirement,
    bind_static_trigger_candidates_to_hardware_references,
    fuse_static_semantic_and_program_structure,
    project_static_semantic_inventory,
    project_static_trigger_candidates,
)
from chipchain.verification import (
    StaticCandidateVerificationRequirement,
    StaticCrossLayerEvidenceRequirementKind,
    StaticCrossLayerVerificationRequirementMaterialization,
    StaticCrossLayerVerificationRequirementProjection,
    project_cross_layer_verification_requirements,
    static_candidate_verification_requirement_id,
    static_cross_layer_binding_verification_requirement_id,
    static_cross_layer_verification_requirement_materialization_id,
    static_cross_layer_verification_requirement_projection_id,
)
pytest.importorskip("angr")

_RUNNER = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts/export_static_cross_layer_candidates.py"),
    run_name="phase10d_requirements_source_runner",
)
build_owned_static_cross_layer_materialization = _RUNNER[
    "build_owned_static_cross_layer_materialization"
]
build_public_a77_static_cross_layer_materialization = _RUNNER[
    "build_public_a77_static_cross_layer_materialization"
]


@pytest.fixture(scope="module")
def owned_source():
    return build_owned_static_cross_layer_materialization()


@pytest.fixture(scope="module")
def owned(owned_source):
    return project_cross_layer_verification_requirements(owned_source)


def _rehash_materialization(payload: dict) -> None:
    projection = payload["projection"]
    projection["id"] = static_cross_layer_verification_requirement_projection_id(
        {k: v for k, v in projection.items() if k != "id"}
    )
    payload["id"] = static_cross_layer_verification_requirement_materialization_id({k: v for k, v in payload.items() if k != "id"})


def _standalone_projection(payload: dict, *, source_count: int = 2):
    return StaticCrossLayerVerificationRequirementProjection.create(
        **{k: v for k, v in payload.items() if k not in {"contract", "id", "diagnostic_codes"}},
        source_case_candidate_count=source_count,
        source_resolved_binding_count=len({item["source_cross_layer_binding_id"] for item in payload["binding_requirements"]}),
    )


def test_owned_counts_and_candidate_deduplication(owned) -> None:
    projection = owned.projection
    assert len({item.source_case_candidate_id for item in projection.candidate_requirements}) == 2
    assert len(projection.candidate_requirements) == 4
    assert len(projection.binding_requirements) == 12
    assert len(projection.source_unresolved_hardware_reference_ids) == 0
    assert len({(item.source_case_candidate_id, item.source_obligation) for item in projection.candidate_requirements}) == 4
    assert len({(item.source_cross_layer_binding_id, item.source_obligation) for item in projection.binding_requirements}) == 12


def test_owned_exact_subject_mapping(owned) -> None:
    for item in owned.projection.candidate_requirements:
        candidate = next(c for c in owned.source_cross_layer_candidate_materialization_snapshot.source_candidate_materialization_snapshot.projection.case_candidates if c.id == item.source_case_candidate_id)
        if item.evidence_requirement_kind is StaticCrossLayerEvidenceRequirementKind.RUNTIME_EXECUTION_TRACE_REQUIRED:
            assert item.subject_position_candidate_ids == sorted(p.id for p in candidate.position_candidates)
            assert item.subject_fused_fact_node_ids == sorted(p.source_fused_fact_node_id for p in candidate.position_candidates)
            assert item.subject_order_witness_ids == sorted(w.id for w in candidate.order_witnesses)
        else:
            cfg = [w for w in candidate.order_witnesses if w.order_basis.value == "directed_function_cfg_path"]
            endpoints = {v for w in cfg for v in (w.source_position_candidate_id, w.target_position_candidate_id)}
            assert item.subject_order_witness_ids == sorted(w.id for w in cfg)
            assert item.subject_position_candidate_ids == sorted(endpoints)
            assert item.subject_fused_fact_node_ids == sorted(
                position.source_fused_fact_node_id
                for position in candidate.position_candidates
                if position.id in endpoints
            )


def test_empty_and_partial_catalog_preserve_candidate_work(owned_source) -> None:
    candidates = owned_source.source_candidate_materialization_snapshot
    empty = bind_static_trigger_candidates_to_hardware_references(candidates, StaticHardwareReferenceCatalog.create(references=[]))
    first_reference = owned_source.source_hardware_reference_catalog_snapshot.references[0]
    partial = bind_static_trigger_candidates_to_hardware_references(candidates, StaticHardwareReferenceCatalog.create(references=[first_reference]))
    full_result = project_cross_layer_verification_requirements(owned_source).projection
    empty_result = project_cross_layer_verification_requirements(empty).projection
    partial_result = project_cross_layer_verification_requirements(partial).projection
    assert (len(empty_result.candidate_requirements), len(empty_result.binding_requirements), len(empty_result.source_unresolved_hardware_reference_ids)) == (4, 0, 4)
    assert (len(partial_result.candidate_requirements), len(partial_result.binding_requirements), len(partial_result.source_unresolved_hardware_reference_ids)) == (4, 6, 2)
    assert len(full_result.binding_requirements) == 12
    expected = [
        item.model_dump(mode="json")
        for item in full_result.candidate_requirements
    ]
    assert [
        item.model_dump(mode="json")
        for item in empty_result.candidate_requirements
    ] == expected
    assert [
        item.model_dump(mode="json")
        for item in partial_result.candidate_requirements
    ] == expected
    assert len({empty_result.id, partial_result.id, full_result.id}) == 3
    empty_materialization = project_cross_layer_verification_requirements(empty)
    partial_materialization = project_cross_layer_verification_requirements(partial)
    full_materialization = project_cross_layer_verification_requirements(owned_source)
    assert len(
        {
            empty_materialization.id,
            partial_materialization.id,
            full_materialization.id,
        }
    ) == 3


def test_public_a77_has_no_verification_subject() -> None:
    source = build_public_a77_static_cross_layer_materialization()
    result = project_cross_layer_verification_requirements(source)
    assert source.projection.bindings == source.projection.unresolved_references == []
    assert result.projection.candidate_requirements == []
    assert result.projection.binding_requirements == []


def _pattern_source(base_source, pattern, *, references=None):
    candidate_source = base_source.source_candidate_materialization_snapshot
    candidates = project_static_trigger_candidates(
        candidate_source.source_fused_graph_materialization_snapshot,
        StaticTriggerPatternCatalog.create(patterns=[pattern]),
    )
    return bind_static_trigger_candidates_to_hardware_references(
        candidates,
        StaticHardwareReferenceCatalog.create(
            references=[] if references is None else references
        ),
    )


def _synthetic_memory_cfg_fused():
    common = {
        "architecture": "arm",
        "artifact_id": "owned-synthetic-requirement-planning-contract",
        "artifact_sha256": "a" * 64,
        "decoder_profile_id": "owned-synthetic-semantic-decoder-v1",
        "instruction_set": "aarch64",
    }
    facts = [
        StaticSemanticInstructionFact.create(
            **common,
            instruction_address="0x500000",
            instruction_bytes="0x01000000",
            instruction_size=4,
            function_address="0x500000",
            function_name="owned_synthetic_requirement_flow",
            basic_block_address="0x500000",
            operation=StaticSemanticOperation.MEMORY_LOAD,
            attributes=[],
            fact_scope=(
                StaticSemanticFactScope
                .DECODED_STATIC_INSTRUCTION_SEMANTICS_ONLY
            ),
        ),
        StaticSemanticInstructionFact.create(
            **common,
            instruction_address="0x500004",
            instruction_bytes="0x02000000",
            instruction_size=4,
            function_address="0x500000",
            function_name="owned_synthetic_requirement_flow",
            basic_block_address="0x500004",
            operation=StaticSemanticOperation.MEMORY_STORE,
            attributes=[],
            fact_scope=(
                StaticSemanticFactScope
                .DECODED_STATIC_INSTRUCTION_SEMANTICS_ONLY
            ),
        ),
    ]
    inventory = StaticSemanticInventory.create(
        **common,
        analysis_scope=(
            StaticSemanticInventoryScope
            .PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY
        ),
        facts=facts,
        diagnostic_codes=["semantic_fact_count:2"],
    )
    semantic_graph = project_static_semantic_inventory(inventory)
    structure_common = {
        "architecture": "arm",
        "artifact_id": common["artifact_id"],
        "artifact_sha256": common["artifact_sha256"],
        "analyzer_profile_id": "owned-synthetic-structure-extractor-v1",
        "instruction_set": "aarch64",
        "function_address": "0x500000",
        "cfg_semantics": (
            StaticProgramCfgSemantics
            .FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1
        ),
    }
    edge = StaticProgramCfgEdge.create(
        **structure_common,
        source_basic_block_address="0x500000",
        target_basic_block_address="0x500004",
    )
    function = StaticProgramFunctionCfg.create(
        **structure_common,
        function_name="owned_synthetic_requirement_flow",
        basic_block_addresses=["0x500000", "0x500004"],
        directed_edges=[edge],
    )
    structure = StaticProgramStructureInventory.create(
        architecture="arm",
        artifact_id=common["artifact_id"],
        artifact_sha256=common["artifact_sha256"],
        analyzer_profile_id="owned-synthetic-structure-extractor-v1",
        instruction_set="aarch64",
        functions=[function],
    )
    return fuse_static_semantic_and_program_structure(semantic_graph, structure)


def _synthetic_source(pattern, *, references=None):
    candidates = project_static_trigger_candidates(
        _synthetic_memory_cfg_fused(),
        StaticTriggerPatternCatalog.create(patterns=[pattern]),
    )
    return bind_static_trigger_candidates_to_hardware_references(
        candidates,
        StaticHardwareReferenceCatalog.create(
            references=[] if references is None else references
        ),
    )


def _memory_context_predicate(operation: str):
    return StaticTriggerPredicate.create(
        operation=operation,
        required_effective_memory_types=["owned-synthetic-normal-memory"],
        required_execution_contexts=["owned-synthetic-el1"],
        objective_requirements=[
            StaticTriggerObjectiveRequirement
            .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
            StaticTriggerObjectiveRequirement.RUNTIME_EXECUTION_CONTEXT_REQUIRED,
        ],
    )


def _single_predicate_pattern(
    predicate,
    *,
    name: str,
    case_requirements=None,
    pattern_requirements=None,
    cases=None,
):
    if cases is None:
        cases = [
            StaticTriggerCase.create(
                case_reference_id=f"{name}-case",
                positions=[
                    StaticTriggerPosition.create(
                        position_index=1,
                        alternatives=[predicate],
                    )
                ],
                objective_requirements=case_requirements or [],
            )
        ]
    return StaticTriggerPattern.create(
        architecture="arm",
        instruction_set="aarch64",
        pattern_name=name,
        source_reference_ids=[f"{name}-design-v1"],
        hardware_reference_ids=[f"{name}-hardware-v1"],
        cases=cases,
        objective_requirements=pattern_requirements or [],
    )


def _all_obligation_source(public_source):
    reference = public_source.source_hardware_reference_catalog_snapshot.references[0]
    positions = [
        StaticTriggerPosition.create(
            position_index=1,
            alternatives=[_memory_context_predicate("memory_load")],
        ),
        StaticTriggerPosition.create(
            position_index=2,
            alternatives=[_memory_context_predicate("memory_store")],
        ),
    ]
    relation = StaticTriggerRelationRequirement.create(
        relation_kind=StaticTriggerRelationKind.CLOSE_PROXIMITY,
        precision=StaticTriggerRelationPrecision.QUALITATIVE_ONLY,
        evaluability=StaticTriggerRelationEvaluability.SOURCE_INSUFFICIENT_FOR_EXACT_STATIC_SATISFACTION,
    )
    new_case = StaticTriggerCase.create(
        case_reference_id="owned-synthetic-all-obligations-case",
        positions=positions, relation_requirement=relation,
        objective_requirements=[StaticTriggerObjectiveRequirement.RELATION_PROXIMITY_REMAINS_UNRESOLVED],
    )
    pattern = StaticTriggerPattern.create(
        architecture="arm", instruction_set="aarch64",
        pattern_name="owned_synthetic_all_obligations_pattern",
        source_reference_ids=["owned-synthetic-all-obligations-design-v1"],
        hardware_reference_ids=[reference.reference_id], cases=[new_case],
        objective_requirements=[StaticTriggerObjectiveRequirement.ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED],
    )
    return _synthetic_source(pattern, references=[reference])


def test_synthetic_source_covers_all_nine_requirement_kinds() -> None:
    public_source = build_public_a77_static_cross_layer_materialization()
    result = project_cross_layer_verification_requirements(
        _all_obligation_source(public_source)
    )
    assert len(result.projection.candidate_requirements) == 6
    assert len(result.projection.binding_requirements) == 3
    assert {item.evidence_requirement_kind for item in [*result.projection.candidate_requirements, *result.projection.binding_requirements]} == set(StaticCrossLayerEvidenceRequirementKind)


@pytest.mark.parametrize(
    ("objective_requirement", "required_field", "message"),
    [
        (
            StaticTriggerObjectiveRequirement
            .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
            "required_effective_memory_types",
            "lacks a declared required memory type",
        ),
        (
            StaticTriggerObjectiveRequirement.RUNTIME_EXECUTION_CONTEXT_REQUIRED,
            "required_execution_contexts",
            "lacks a declared required execution context",
        ),
    ],
)
def test_selected_predicate_obligation_requires_nonempty_source_declaration(
    objective_requirement, required_field, message
) -> None:
    values = {
        "operation": "memory_load",
        "required_effective_memory_types": [],
        "required_execution_contexts": [],
        "objective_requirements": [objective_requirement],
    }
    values[required_field] = []
    predicate = StaticTriggerPredicate.create(**values)
    pattern = _single_predicate_pattern(
        predicate,
        name=f"owned-synthetic-malformed-{required_field}",
    )
    source = _synthetic_source(pattern)
    assert source.source_candidate_materialization_snapshot.projection.case_candidates
    with pytest.raises(ValueError, match=message):
        project_cross_layer_verification_requirements(source)


def test_memory_and_context_requirements_aggregate_all_contributors() -> None:
    public_source = build_public_a77_static_cross_layer_materialization()
    result = project_cross_layer_verification_requirements(
        _all_obligation_source(public_source)
    )
    candidate = (
        result.source_cross_layer_candidate_materialization_snapshot
        .source_candidate_materialization_snapshot.projection.case_candidates[0]
    )
    for kind in (
        StaticCrossLayerEvidenceRequirementKind
        .EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED,
        StaticCrossLayerEvidenceRequirementKind.EXECUTION_CONTEXT_EVIDENCE_REQUIRED,
    ):
        requirements = [
            item
            for item in result.projection.candidate_requirements
            if item.evidence_requirement_kind is kind
        ]
        assert len(requirements) == 1
        assert requirements[0].subject_position_candidate_ids == sorted(
            item.id for item in candidate.position_candidates
        )
        assert requirements[0].subject_fused_fact_node_ids == sorted(
            item.source_fused_fact_node_id for item in candidate.position_candidates
        )
        assert len(requirements[0].subject_position_candidate_ids) == 2


def test_only_selected_or_predicate_contributes_memory_obligation() -> None:
    public_source = build_public_a77_static_cross_layer_materialization()
    first = StaticTriggerPredicate.create(operation="memory_load")
    with_memory = StaticTriggerPredicate.create(
        operation="memory_load",
        required_effective_memory_types=["owned-synthetic-normal-memory"],
        objective_requirements=[StaticTriggerObjectiveRequirement.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED],
    )
    positions = [
        StaticTriggerPosition.create(position_index=1, alternatives=[first, with_memory]),
    ]
    selected_case = StaticTriggerCase.create(case_reference_id="owned-synthetic-or-selection", positions=positions)
    pattern = StaticTriggerPattern.create(
        architecture="arm", instruction_set="aarch64",
        pattern_name="owned_synthetic_or_selection_pattern",
        source_reference_ids=["owned-synthetic-or-selection-design-v1"],
        hardware_reference_ids=[
            public_source.source_hardware_reference_catalog_snapshot.references[
                0
            ].reference_id
        ], cases=[selected_case],
    )
    source = _pattern_source(public_source, pattern)
    candidates = source.source_candidate_materialization_snapshot
    result = project_cross_layer_verification_requirements(source)
    memory_requirements = [item for item in result.projection.candidate_requirements if item.evidence_requirement_kind is StaticCrossLayerEvidenceRequirementKind.EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED]
    selected_by_candidate = {item.id: item.position_candidates[0].source_predicate_id for item in candidates.projection.case_candidates}
    assert len(memory_requirements) == 1
    assert selected_by_candidate[memory_requirements[0].source_case_candidate_id] == with_memory.id
    no_memory_candidate_ids = {
        candidate_id for candidate_id, predicate_id in selected_by_candidate.items()
        if predicate_id == first.id
    }
    assert no_memory_candidate_ids
    assert no_memory_candidate_ids.isdisjoint(
        item.source_case_candidate_id for item in memory_requirements
    )


def test_only_selected_or_predicate_contributes_context_obligation() -> None:
    public_source = build_public_a77_static_cross_layer_materialization()
    plain = StaticTriggerPredicate.create(operation="memory_load")
    with_context = StaticTriggerPredicate.create(
        operation="memory_load",
        required_execution_contexts=["owned-synthetic-el1"],
        objective_requirements=[
            StaticTriggerObjectiveRequirement.RUNTIME_EXECUTION_CONTEXT_REQUIRED
        ],
    )
    case = StaticTriggerCase.create(
        case_reference_id="owned-synthetic-context-or-selection",
        positions=[
            StaticTriggerPosition.create(
                position_index=1,
                alternatives=[plain, with_context],
            )
        ],
    )
    pattern = _single_predicate_pattern(
        plain,
        name="owned-synthetic-context-or-selection-pattern",
        cases=[case],
    )
    source = _pattern_source(public_source, pattern)
    result = project_cross_layer_verification_requirements(source)
    candidates = source.source_candidate_materialization_snapshot.projection.case_candidates
    selected = {
        item.id: item.position_candidates[0].source_predicate_id
        for item in candidates
    }
    context_requirements = [
        item
        for item in result.projection.candidate_requirements
        if item.evidence_requirement_kind
        is StaticCrossLayerEvidenceRequirementKind
        .EXECUTION_CONTEXT_EVIDENCE_REQUIRED
    ]
    assert len(context_requirements) == 1
    assert selected[context_requirements[0].source_case_candidate_id] == with_context.id
    plain_candidate_ids = {
        candidate_id
        for candidate_id, predicate_id in selected.items()
        if predicate_id == plain.id
    }
    assert plain_candidate_ids
    assert plain_candidate_ids.isdisjoint(
        item.source_case_candidate_id for item in context_requirements
    )


def test_proximity_and_timing_require_exact_source_declarations(owned) -> None:
    kinds = {
        item.evidence_requirement_kind
        for item in owned.projection.candidate_requirements
    }
    assert (
        StaticCrossLayerEvidenceRequirementKind
        .QUALITATIVE_PROXIMITY_EVIDENCE_REQUIRED
        not in kinds
    )
    assert (
        StaticCrossLayerEvidenceRequirementKind.HARDWARE_TIMING_EVIDENCE_REQUIRED
        not in kinds
    )

    public_source = build_public_a77_static_cross_layer_materialization()
    all_nine = project_cross_layer_verification_requirements(
        _all_obligation_source(public_source)
    )
    candidate = (
        all_nine.source_cross_layer_candidate_materialization_snapshot
        .source_candidate_materialization_snapshot.projection.case_candidates[0]
    )
    full_positions = sorted(item.id for item in candidate.position_candidates)
    full_facts = sorted(
        item.source_fused_fact_node_id for item in candidate.position_candidates
    )
    for kind in (
        StaticCrossLayerEvidenceRequirementKind
        .QUALITATIVE_PROXIMITY_EVIDENCE_REQUIRED,
        StaticCrossLayerEvidenceRequirementKind.HARDWARE_TIMING_EVIDENCE_REQUIRED,
    ):
        requirement = next(
            item
            for item in all_nine.projection.candidate_requirements
            if item.evidence_requirement_kind is kind
        )
        assert requirement.subject_position_candidate_ids == full_positions
        assert requirement.subject_fused_fact_node_ids == full_facts


def test_same_pattern_multiple_cases_keep_distinct_timing_requirements() -> None:
    cases = [
        StaticTriggerCase.create(
            case_reference_id=f"owned-synthetic-timing-case-{index}",
            positions=[
                StaticTriggerPosition.create(
                    position_index=1,
                    alternatives=[
                        StaticTriggerPredicate.create(operation=operation)
                    ],
                )
            ],
        )
        for index, operation in enumerate(("memory_load", "memory_store"), 1)
    ]
    pattern = _single_predicate_pattern(
        StaticTriggerPredicate.create(operation="memory_load"),
        name="owned-synthetic-multi-case-timing",
        cases=cases,
        pattern_requirements=[
            StaticTriggerObjectiveRequirement
            .ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED
        ],
    )
    result = project_cross_layer_verification_requirements(
        _synthetic_source(pattern)
    )
    timing = [
        item
        for item in result.projection.candidate_requirements
        if item.evidence_requirement_kind
        is StaticCrossLayerEvidenceRequirementKind.HARDWARE_TIMING_EVIDENCE_REQUIRED
    ]
    assert len(timing) == 2
    assert len({item.source_case_candidate_id for item in timing}) == 2


def test_same_block_candidate_does_not_gain_path_feasibility_requirement() -> None:
    public_source = build_public_a77_static_cross_layer_materialization()
    candidates_source = public_source.source_candidate_materialization_snapshot
    reference = public_source.source_hardware_reference_catalog_snapshot.references[0]
    store = StaticTriggerPredicate.create(operation="memory_store")
    exclusive = StaticTriggerPredicate.create(operation="load_exclusive")
    case = StaticTriggerCase.create(
        case_reference_id="owned-synthetic-same-block-order",
        positions=[
            StaticTriggerPosition.create(position_index=1, alternatives=[store]),
            StaticTriggerPosition.create(position_index=2, alternatives=[exclusive]),
        ],
    )
    pattern = StaticTriggerPattern.create(
        architecture="arm", instruction_set="aarch64",
        pattern_name="owned_synthetic_same_block_pattern",
        source_reference_ids=["owned-synthetic-same-block-design-v1"],
        hardware_reference_ids=[reference.reference_id], cases=[case],
    )
    candidates = project_static_trigger_candidates(
        candidates_source.source_fused_graph_materialization_snapshot,
        StaticTriggerPatternCatalog.create(patterns=[pattern]),
    )
    assert candidates.projection.case_candidates
    assert all(w.order_basis.value == "same_basic_block_static_instruction_order" for c in candidates.projection.case_candidates for w in c.order_witnesses)
    source = bind_static_trigger_candidates_to_hardware_references(candidates, StaticHardwareReferenceCatalog.create(references=[reference]))
    result = project_cross_layer_verification_requirements(source)
    assert all(item.evidence_requirement_kind is not StaticCrossLayerEvidenceRequirementKind.PATH_FEASIBILITY_EVIDENCE_REQUIRED for item in result.projection.candidate_requirements)


@pytest.mark.parametrize(
    "field",
    [
        "subject_order_witness_ids",
        "subject_position_candidate_ids",
        "subject_fused_fact_node_ids",
    ],
)
def test_standalone_path_requirement_rejects_incomplete_subject(
    owned, field
) -> None:
    requirement = next(
        item
        for item in owned.projection.candidate_requirements
        if item.evidence_requirement_kind
        is StaticCrossLayerEvidenceRequirementKind
        .PATH_FEASIBILITY_EVIDENCE_REQUIRED
    )
    payload = requirement.model_dump(mode="json")
    payload[field] = []
    payload["id"] = static_candidate_verification_requirement_id(
        {key: value for key, value in payload.items() if key != "id"}
    )
    with pytest.raises(ValidationError):
        StaticCandidateVerificationRequirement.model_validate(payload)


@pytest.mark.parametrize(
    "field",
    ["subject_position_candidate_ids", "subject_fused_fact_node_ids"],
)
def test_standalone_runtime_requirement_rejects_empty_subject(
    owned, field
) -> None:
    requirement = next(
        item
        for item in owned.projection.candidate_requirements
        if item.evidence_requirement_kind
        is StaticCrossLayerEvidenceRequirementKind.RUNTIME_EXECUTION_TRACE_REQUIRED
    )
    payload = requirement.model_dump(mode="json")
    payload[field] = []
    payload["id"] = static_candidate_verification_requirement_id(
        {key: value for key, value in payload.items() if key != "id"}
    )
    with pytest.raises(ValidationError):
        StaticCandidateVerificationRequirement.model_validate(payload)


def test_standalone_memory_and_context_requirements_reject_empty_subjects() -> None:
    public_source = build_public_a77_static_cross_layer_materialization()
    materialization = project_cross_layer_verification_requirements(
        _all_obligation_source(public_source)
    )
    for requirement in materialization.projection.candidate_requirements:
        if requirement.evidence_requirement_kind not in {
            StaticCrossLayerEvidenceRequirementKind
            .EFFECTIVE_MEMORY_TYPE_EVIDENCE_REQUIRED,
            StaticCrossLayerEvidenceRequirementKind
            .EXECUTION_CONTEXT_EVIDENCE_REQUIRED,
        }:
            continue
        for field in (
            "subject_position_candidate_ids",
            "subject_fused_fact_node_ids",
        ):
            payload = requirement.model_dump(mode="json")
            payload[field] = []
            payload["id"] = static_candidate_verification_requirement_id(
                {key: value for key, value in payload.items() if key != "id"}
            )
            with pytest.raises(ValidationError):
                StaticCandidateVerificationRequirement.model_validate(payload)


def test_rehashed_foreign_candidate_requirement_is_rejected_by_authority(owned) -> None:
    payload = owned.model_dump(mode="json")
    requirement = payload["projection"]["candidate_requirements"][0]
    requirement["source_case_candidate_id"] = "static-trigger-case-candidate:foreign"
    requirement["id"] = static_candidate_verification_requirement_id({k: v for k, v in requirement.items() if k != "id"})
    projection = _standalone_projection(payload["projection"], source_count=3)
    payload["projection"] = projection.model_dump(mode="json")
    _rehash_materialization(payload)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticCrossLayerVerificationRequirementMaterialization.model_validate(payload)


def test_rehashed_foreign_fact_passes_standalone_but_authority_rejects(
    owned,
) -> None:
    payload = owned.model_dump(mode="json")
    requirement = next(
        item
        for item in payload["projection"]["candidate_requirements"]
        if item["source_obligation"] == "runtime_execution_required"
    )
    used = set(requirement["subject_fused_fact_node_ids"])
    candidates = (
        owned.source_cross_layer_candidate_materialization_snapshot
        .source_candidate_materialization_snapshot.projection.case_candidates
    )
    foreign = next(
        position.source_fused_fact_node_id
        for candidate in candidates
        for position in candidate.position_candidates
        if position.source_fused_fact_node_id not in used
    )
    requirement["subject_fused_fact_node_ids"][0] = foreign
    requirement["id"] = static_candidate_verification_requirement_id(
        {key: value for key, value in requirement.items() if key != "id"}
    )
    projection = _standalone_projection(payload["projection"])
    payload["projection"] = projection.model_dump(mode="json")
    _rehash_materialization(payload)
    assert projection.candidate_requirements
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticCrossLayerVerificationRequirementMaterialization.model_validate(payload)


def test_rehashed_foreign_selected_position_passes_standalone_but_authority_rejects() -> None:
    public_source = build_public_a77_static_cross_layer_materialization()
    context = StaticTriggerPredicate.create(
        operation="memory_store",
        required_execution_contexts=["owned-synthetic-el1"],
        objective_requirements=[
            StaticTriggerObjectiveRequirement.RUNTIME_EXECUTION_CONTEXT_REQUIRED
        ],
    )
    plain = StaticTriggerPredicate.create(operation="load_exclusive")
    case = StaticTriggerCase.create(
        case_reference_id="owned-synthetic-foreign-position-case",
        positions=[
            StaticTriggerPosition.create(
                position_index=1, alternatives=[context]
            ),
            StaticTriggerPosition.create(
                position_index=2, alternatives=[plain]
            ),
        ],
    )
    pattern = _single_predicate_pattern(
        context,
        name="owned-synthetic-foreign-position-pattern",
        cases=[case],
    )
    value = project_cross_layer_verification_requirements(
        _pattern_source(public_source, pattern)
    )
    source_candidate = (
        value.source_cross_layer_candidate_materialization_snapshot
        .source_candidate_materialization_snapshot.projection.case_candidates[0]
    )
    payload = value.model_dump(mode="json")
    requirement = next(
        item
        for item in payload["projection"]["candidate_requirements"]
        if item["source_obligation"] == "runtime_execution_context_required"
    )
    foreign_position = source_candidate.position_candidates[1]
    assert foreign_position.id not in requirement["subject_position_candidate_ids"]
    requirement["subject_position_candidate_ids"] = [foreign_position.id]
    requirement["id"] = static_candidate_verification_requirement_id(
        {key: field for key, field in requirement.items() if key != "id"}
    )
    projection = _standalone_projection(payload["projection"], source_count=1)
    payload["projection"] = projection.model_dump(mode="json")
    _rehash_materialization(payload)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticCrossLayerVerificationRequirementMaterialization.model_validate(payload)


def test_rehashed_foreign_cfg_witness_passes_standalone_but_authority_rejects(
    owned,
) -> None:
    payload = owned.model_dump(mode="json")
    path_requirements = [
        item
        for item in payload["projection"]["candidate_requirements"]
        if item["source_obligation"]
        == "symbolic_path_feasibility_remains_unresolved"
    ]
    target = path_requirements[0]
    foreign = next(
        witness
        for other in path_requirements[1:]
        for witness in other["subject_order_witness_ids"]
        if witness not in target["subject_order_witness_ids"]
    )
    target["subject_order_witness_ids"][0] = foreign
    target["id"] = static_candidate_verification_requirement_id(
        {key: value for key, value in target.items() if key != "id"}
    )
    projection = _standalone_projection(payload["projection"])
    payload["projection"] = projection.model_dump(mode="json")
    _rehash_materialization(payload)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticCrossLayerVerificationRequirementMaterialization.model_validate(payload)


def test_rehashed_wrong_obligation_is_rejected_by_authority(owned) -> None:
    payload = owned.model_dump(mode="json")
    requirement = next(item for item in payload["projection"]["candidate_requirements"] if item["source_obligation"] == "runtime_execution_required")
    requirement["source_obligation"] = "additional_hardware_timing_remains_unresolved"
    requirement["evidence_requirement_kind"] = "hardware_timing_evidence_required"
    requirement["id"] = static_candidate_verification_requirement_id({k: v for k, v in requirement.items() if k != "id"})
    payload["projection"] = _standalone_projection(payload["projection"]).model_dump(mode="json")
    _rehash_materialization(payload)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticCrossLayerVerificationRequirementMaterialization.model_validate(payload)


def test_rehashed_foreign_binding_assignment_is_rejected(owned) -> None:
    payload = owned.model_dump(mode="json")
    requirements = payload["projection"]["binding_requirements"]
    first = requirements[0]
    second = next(item for item in requirements if item["source_cross_layer_binding_id"] != first["source_cross_layer_binding_id"])
    source_binding_id = first["source_cross_layer_binding_id"]
    targets = [item for item in requirements if item["source_cross_layer_binding_id"] == source_binding_id]
    for item in targets:
        for field in ["source_case_candidate_id", "source_pattern_id", "source_hardware_reference_id", "source_hardware_reference_record_id"]:
            item[field] = second[field]
        item["id"] = static_cross_layer_binding_verification_requirement_id({k: v for k, v in item.items() if k != "id"})
    payload["projection"] = _standalone_projection(payload["projection"]).model_dump(mode="json")
    _rehash_materialization(payload)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticCrossLayerVerificationRequirementMaterialization.model_validate(payload)


def test_rehashed_foreign_binding_id_is_rejected_by_authority(owned) -> None:
    payload = owned.model_dump(mode="json")
    requirements = payload["projection"]["binding_requirements"]
    binding_ids = sorted({item["source_cross_layer_binding_id"] for item in requirements})
    first_id, second_id = binding_ids[:2]
    for item in requirements:
        if item["source_cross_layer_binding_id"] == first_id:
            item["source_cross_layer_binding_id"] = second_id
        elif item["source_cross_layer_binding_id"] == second_id:
            item["source_cross_layer_binding_id"] = first_id
        else:
            continue
        item["id"] = static_cross_layer_binding_verification_requirement_id(
            {key: value for key, value in item.items() if key != "id"}
        )
    projection = _standalone_projection(payload["projection"])
    payload["projection"] = projection.model_dump(mode="json")
    _rehash_materialization(payload)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticCrossLayerVerificationRequirementMaterialization.model_validate(payload)


@pytest.mark.parametrize("mode", ["missing", "extra"])
def test_missing_or_extra_requirement_is_rejected(owned, mode) -> None:
    payload = owned.model_dump(mode="json")
    projection = payload["projection"]
    if mode == "missing":
        projection["binding_requirements"].pop()
    else:
        base = next(item for item in projection["candidate_requirements"] if item["source_obligation"] == "runtime_execution_required")
        extra = copy.deepcopy(base)
        extra["source_obligation"] = "additional_hardware_timing_remains_unresolved"
        extra["evidence_requirement_kind"] = "hardware_timing_evidence_required"
        extra["id"] = static_candidate_verification_requirement_id({k: v for k, v in extra.items() if k != "id"})
        projection["candidate_requirements"].append(extra)
    payload["projection"] = _standalone_projection(projection).model_dump(mode="json")
    _rehash_materialization(payload)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticCrossLayerVerificationRequirementMaterialization.model_validate(payload)


def test_invalid_nested_cross_layer_source_snapshot_is_rejected(owned) -> None:
    payload = owned.model_dump(mode="json")
    nested = payload["source_cross_layer_candidate_materialization_snapshot"]
    nested["projection"]["bindings"].pop()
    payload["id"] = static_cross_layer_verification_requirement_materialization_id(
        {key: value for key, value in payload.items() if key != "id"}
    )
    with pytest.raises(ValidationError):
        StaticCrossLayerVerificationRequirementMaterialization.model_validate(payload)


def test_different_valid_cross_layer_source_snapshot_is_rejected(
    owned, owned_source
) -> None:
    empty_source = bind_static_trigger_candidates_to_hardware_references(
        owned_source.source_candidate_materialization_snapshot,
        StaticHardwareReferenceCatalog.create(references=[]),
    )
    payload = owned.model_dump(mode="json")
    payload["source_cross_layer_candidate_materialization_id"] = empty_source.id
    payload["source_cross_layer_candidate_materialization_snapshot"] = (
        empty_source.model_dump(mode="json")
    )
    payload["id"] = static_cross_layer_verification_requirement_materialization_id(
        {key: value for key, value in payload.items() if key != "id"}
    )
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticCrossLayerVerificationRequirementMaterialization.model_validate(payload)


@pytest.mark.parametrize(
    "mutation",
    [
        {"source_candidate_materialization_id": "candidate-materialization:different"},
        {"source_candidate_projection_id": "candidate-projection:different"},
        {"source_case_candidate_id": "case-candidate:different"},
        {"source_pattern_id": "pattern:different"},
        {"source_pattern_case_id": "pattern-case:different"},
        {
            "source_obligation": "additional_hardware_timing_remains_unresolved",
            "evidence_requirement_kind": "hardware_timing_evidence_required",
        },
        {"subject_position_candidate_ids": ["position-candidate:different"]},
        {"subject_fused_fact_node_ids": ["fused-fact:different"]},
        {"subject_order_witness_ids": ["order-witness:different"]},
    ],
)
def test_candidate_requirement_identity_binds_every_candidate_semantic_field(
    owned, mutation
) -> None:
    original = next(
        item
        for item in owned.projection.candidate_requirements
        if item.evidence_requirement_kind
        is StaticCrossLayerEvidenceRequirementKind.RUNTIME_EXECUTION_TRACE_REQUIRED
    )
    values = original.model_dump(mode="python", exclude={"contract", "id"})
    values.update(mutation)
    changed = StaticCandidateVerificationRequirement.create(**values)
    assert changed.id != original.id


def test_caller_mutation_is_detached(owned_source) -> None:
    caller_source = type(owned_source).model_validate(
        owned_source.model_dump(mode="json")
    )
    result = project_cross_layer_verification_requirements(caller_source)
    retained = result.model_dump(mode="json")
    caller_source.projection.bindings.clear()
    caller_source.source_hardware_reference_catalog_snapshot.references.clear()
    assert result.model_dump(mode="json") == retained
    subjects = ["position:one"]
    base = result.projection.candidate_requirements[0]
    created = StaticCandidateVerificationRequirement.create(
        **base.model_dump(mode="python", exclude={"contract", "id", "subject_position_candidate_ids"}),
        subject_position_candidate_ids=subjects,
    )
    subjects.append("position:two")
    assert created.subject_position_candidate_ids == ["position:one"]
    candidate_list = list(result.projection.candidate_requirements)
    copied_projection = StaticCrossLayerVerificationRequirementProjection.create(
        **result.projection.model_dump(
            mode="python", exclude={"contract", "id", "diagnostic_codes", "candidate_requirements"}
        ),
        candidate_requirements=candidate_list,
        source_case_candidate_count=2,
        source_resolved_binding_count=4,
    )
    candidate_list.clear()
    assert len(copied_projection.candidate_requirements) == 4


def test_projection_is_deterministic_across_ten_runs() -> None:
    source = build_owned_static_cross_layer_materialization()
    source_payload = source.model_dump(mode="json")
    permuted_payload = copy.deepcopy(source_payload)
    permuted_payload["projection"]["bindings"].reverse()
    candidate_snapshot = permuted_payload["source_candidate_materialization_snapshot"]
    candidate_snapshot["projection"]["case_candidates"].reverse()
    candidate_snapshot["source_pattern_catalog_snapshot"]["patterns"].reverse()
    for pattern in candidate_snapshot["source_pattern_catalog_snapshot"]["patterns"]:
        pattern["cases"].reverse()
    permuted_payload["source_hardware_reference_catalog_snapshot"]["references"].reverse()
    permuted = type(source).model_validate(permuted_payload)
    assert permuted == source
    results = [
        project_cross_layer_verification_requirements(
            source if index % 2 == 0 else permuted
        )
        for index in range(10)
    ]
    assert len({item.id for item in results}) == 1
    assert len({item.projection.id for item in results}) == 1
    assert len({hashlib.sha256(json.dumps(item.projection.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()).hexdigest() for item in results}) == 1
