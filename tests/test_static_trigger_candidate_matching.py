"""Contracts for pure deterministic static trigger candidate matching."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from pathlib import Path

from pydantic import ValidationError
import pytest

from chipchain.analysis import (
    AngrAArch64StaticProgramStructureExtractor,
    AngrAArch64StaticSemanticDecoder,
    PHASE10D_STATIC_TRIGGER_CANDIDATE_MATERIALIZATION_CONTRACT,
    PHASE10D_STATIC_TRIGGER_CANDIDATE_PROJECTION_CONTRACT,
    PHASE10D_STATIC_TRIGGER_CASE_CANDIDATE_CONTRACT,
    PHASE10D_STATIC_TRIGGER_ORDER_WITNESS_CONTRACT,
    PHASE10D_STATIC_TRIGGER_POSITION_CANDIDATE_CONTRACT,
    ProgramArtifact,
    StaticProgramCfgEdge,
    StaticProgramCfgSemantics,
    StaticProgramFunctionCfg,
    StaticProgramStructureInventory,
    StaticFusedBehaviorNodeKind,
    StaticFusedBehaviorRelationKind,
    StaticSemanticAttribute,
    StaticSemanticAttributeName,
    StaticSemanticFactScope,
    StaticSemanticInstructionFact,
    StaticSemanticInventory,
    StaticSemanticInventoryScope,
    StaticSemanticOperation,
    StaticTriggerCandidateMaterialization,
    StaticTriggerCandidateObjectiveObligation,
    StaticTriggerCandidateProjection,
    StaticTriggerCandidateSemantics,
    StaticTriggerCase,
    StaticTriggerCaseCandidate,
    StaticTriggerOrderBasis,
    StaticTriggerOrderWitness,
    StaticTriggerPathWitnessUse,
    StaticTriggerPattern,
    StaticTriggerPatternCatalog,
    StaticTriggerPosition,
    StaticTriggerPositionCandidate,
    StaticTriggerPredicate,
    fuse_static_semantic_and_program_structure,
    project_static_semantic_inventory,
    project_static_trigger_candidates,
    static_trigger_candidate_materialization_id,
    static_trigger_candidate_projection_id,
    static_trigger_case_candidate_id,
    static_trigger_order_witness_id,
    static_trigger_position_candidate_id,
)
from chipchain.analysis.static_trigger_pattern_models import (
    StaticTriggerObjectiveRequirement,
    StaticTriggerRelationEvaluability,
    StaticTriggerRelationKind,
    StaticTriggerRelationPrecision,
    StaticTriggerRelationRequirement,
)
from chipchain.models import Architecture


ROOT = Path(__file__).resolve().parents[1]
FUSED_ELF = (
    ROOT
    / "tests/fixtures/phase10d/aarch64_static_fused_behavior_v1/"
    "aarch64_static_fused_behavior_v1.elf"
)
PATTERN_JSON = (
    ROOT
    / "tests/fixtures/phase10d/static_trigger_pattern_v1/"
    "owned_synthetic_static_trigger_pattern_v1.json"
)
ARTIFACT_ID = "owned-synthetic-aarch64-static-fused-behavior-v1"
ARTIFACT_SHA = "a" * 64
CFG_SEMANTICS = (
    StaticProgramCfgSemantics
    .FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1
)


def _attribute(name: StaticSemanticAttributeName, value: str):
    return StaticSemanticAttribute(name=name, value=value)


def _required_attributes(operation: StaticSemanticOperation):
    if operation is StaticSemanticOperation.SYSTEM_REGISTER_READ:
        return [_attribute(StaticSemanticAttributeName.SYSTEM_REGISTER, "par_el1")]
    if operation is StaticSemanticOperation.MEMORY_BARRIER:
        return [_attribute(StaticSemanticAttributeName.BARRIER_KIND, "dsb")]
    if operation is StaticSemanticOperation.INSTRUCTION_BARRIER:
        return [_attribute(StaticSemanticAttributeName.BARRIER_KIND, "isb")]
    if operation is StaticSemanticOperation.TLB_INVALIDATE:
        return [_attribute(StaticSemanticAttributeName.TLB_OPERATION, "vmalle1is")]
    if operation in {
        StaticSemanticOperation.LOAD_EXCLUSIVE,
        StaticSemanticOperation.STORE_EXCLUSIVE,
    }:
        return [
            _attribute(
                StaticSemanticAttributeName.MEMORY_EXCLUSIVITY,
                "exclusive",
            )
        ]
    return []


def _fact(
    *,
    index: int,
    operation: StaticSemanticOperation,
    address: str,
    block: str | None,
    function: str | None = "0x500000",
    architecture: Architecture = Architecture.ARM,
    instruction_set: str = "aarch64",
    attributes: list[StaticSemanticAttribute] | None = None,
) -> StaticSemanticInstructionFact:
    return StaticSemanticInstructionFact.create(
        architecture=architecture,
        artifact_id="owned-synthetic-candidate-contract",
        artifact_sha256=ARTIFACT_SHA,
        decoder_profile_id="owned-synthetic-semantic-decoder-v1",
        instruction_set=instruction_set,
        instruction_address=address,
        instruction_bytes=f"0x{index:08x}",
        instruction_size=4,
        function_address=function,
        function_name=(f"function_{function}" if function else None),
        basic_block_address=block,
        operation=operation,
        attributes=(
            _required_attributes(operation)
            if attributes is None
            else attributes
        ),
        fact_scope=(
            StaticSemanticFactScope.DECODED_STATIC_INSTRUCTION_SEMANTICS_ONLY
        ),
    )


def _synthetic_fused(
    *,
    facts: list[StaticSemanticInstructionFact],
    blocks_by_function: dict[str, list[str]],
    edges_by_function: dict[str, list[tuple[str, str]]],
    architecture: Architecture = Architecture.ARM,
    instruction_set: str = "aarch64",
):
    inventory = StaticSemanticInventory.create(
        architecture=architecture,
        artifact_id="owned-synthetic-candidate-contract",
        artifact_sha256=ARTIFACT_SHA,
        decoder_profile_id="owned-synthetic-semantic-decoder-v1",
        instruction_set=instruction_set,
        analysis_scope=(
            StaticSemanticInventoryScope
            .PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY
        ),
        facts=facts,
        diagnostic_codes=[f"semantic_fact_count:{len(facts)}"],
    )
    semantic_graph = project_static_semantic_inventory(inventory)
    functions = []
    for function_address, block_addresses in blocks_by_function.items():
        common = {
            "architecture": architecture,
            "artifact_id": "owned-synthetic-candidate-contract",
            "artifact_sha256": ARTIFACT_SHA,
            "analyzer_profile_id": "owned-synthetic-structure-extractor-v1",
            "instruction_set": instruction_set,
            "function_address": function_address,
            "cfg_semantics": CFG_SEMANTICS,
        }
        edges = [
            StaticProgramCfgEdge.create(
                **common,
                source_basic_block_address=source,
                target_basic_block_address=target,
            )
            for source, target in edges_by_function.get(function_address, [])
        ]
        functions.append(
            StaticProgramFunctionCfg.create(
                **common,
                function_name=f"function_{function_address}",
                basic_block_addresses=block_addresses,
                directed_edges=edges,
            )
        )
    structure = StaticProgramStructureInventory.create(
        architecture=architecture,
        artifact_id="owned-synthetic-candidate-contract",
        artifact_sha256=ARTIFACT_SHA,
        analyzer_profile_id="owned-synthetic-structure-extractor-v1",
        instruction_set=instruction_set,
        functions=functions,
    )
    return fuse_static_semantic_and_program_structure(
        semantic_graph, structure
    )


def _predicate(
    operation: StaticSemanticOperation,
    *,
    attributes: list[StaticSemanticAttribute] | None = None,
    memory_types: list[str] | None = None,
    contexts: list[str] | None = None,
    requirements: list[StaticTriggerObjectiveRequirement] | None = None,
) -> StaticTriggerPredicate:
    return StaticTriggerPredicate.create(
        operation=operation,
        required_attributes=attributes or [],
        required_effective_memory_types=memory_types or [],
        required_execution_contexts=contexts or [],
        objective_requirements=requirements or [],
    )


def _pattern(
    positions: list[list[StaticTriggerPredicate]],
    *,
    architecture: Architecture = Architecture.ARM,
    instruction_set: str = "aarch64",
    pattern_requirements: list[StaticTriggerObjectiveRequirement] | None = None,
    case_requirements: list[StaticTriggerObjectiveRequirement] | None = None,
    relation: bool = False,
    name: str = "owned_synthetic_candidate_pattern",
) -> StaticTriggerPattern:
    source_positions = [
        StaticTriggerPosition.create(
            position_index=index,
            alternatives=alternatives,
        )
        for index, alternatives in enumerate(positions, start=1)
    ]
    relation_requirement = None
    if relation:
        relation_requirement = StaticTriggerRelationRequirement.create(
            relation_kind=StaticTriggerRelationKind.CLOSE_PROXIMITY,
            precision=StaticTriggerRelationPrecision.QUALITATIVE_ONLY,
            quantitative_bound=None,
            evaluability=(
                StaticTriggerRelationEvaluability
                .SOURCE_INSUFFICIENT_FOR_EXACT_STATIC_SATISFACTION
            ),
        )
    case = StaticTriggerCase.create(
        case_reference_id="owned-case",
        positions=source_positions,
        relation_requirement=relation_requirement,
        objective_requirements=case_requirements or [],
    )
    return StaticTriggerPattern.create(
        architecture=architecture,
        instruction_set=instruction_set,
        pattern_name=name,
        source_reference_ids=[f"{name}-source-v1"],
        hardware_reference_ids=[f"{name}-hardware-condition-v1"],
        cases=[case],
        objective_requirements=pattern_requirements or [],
    )


def _materialize(fused, *patterns):
    catalog = StaticTriggerPatternCatalog.create(patterns=list(patterns))
    return project_static_trigger_candidates(fused, catalog)


@pytest.fixture(scope="module")
def owned_fused():
    pytest.importorskip("angr")
    artifact = ProgramArtifact(
        id=ARTIFACT_ID,
        architecture=Architecture.ARM,
        artifact_type="elf",
        path=str(FUSED_ELF),
        fixture_identifier="phase10d-aarch64-static-fused-behavior-v1",
        metadata={"owned": True, "synthetic": True, "fixture": True},
    )
    semantic = AngrAArch64StaticSemanticDecoder().decode(artifact)
    graph = project_static_semantic_inventory(semantic)
    structure = AngrAArch64StaticProgramStructureExtractor().extract(artifact)
    return fuse_static_semantic_and_program_structure(graph, structure)


@pytest.fixture(scope="module")
def owned_pattern():
    return StaticTriggerPattern.model_validate_json(PATTERN_JSON.read_bytes())


@pytest.fixture(scope="module")
def owned(owned_fused, owned_pattern):
    return _materialize(owned_fused, owned_pattern)


def test_public_api_has_exactly_two_logical_inputs() -> None:
    signature = inspect.signature(project_static_trigger_candidates)
    assert list(signature.parameters) == [
        "fused_graph_materialization",
        "pattern_catalog",
    ]


def test_contract_family_and_closed_vocabularies() -> None:
    assert PHASE10D_STATIC_TRIGGER_POSITION_CANDIDATE_CONTRACT.endswith(
        "position_candidate_v1"
    )
    assert PHASE10D_STATIC_TRIGGER_ORDER_WITNESS_CONTRACT.endswith(
        "order_witness_v1"
    )
    assert PHASE10D_STATIC_TRIGGER_CASE_CANDIDATE_CONTRACT.endswith(
        "case_candidate_v1"
    )
    assert PHASE10D_STATIC_TRIGGER_CANDIDATE_PROJECTION_CONTRACT.endswith(
        "candidate_projection_v1"
    )
    assert PHASE10D_STATIC_TRIGGER_CANDIDATE_MATERIALIZATION_CONTRACT.endswith(
        "candidate_materialization_v1"
    )
    assert list(StaticTriggerCandidateSemantics) == [
        StaticTriggerCandidateSemantics
        .STATIC_STRUCTURAL_PATTERN_CANDIDATE_ONLY
    ]
    assert list(StaticTriggerOrderBasis) == [
        StaticTriggerOrderBasis.SAME_BASIC_BLOCK_STATIC_INSTRUCTION_ORDER,
        StaticTriggerOrderBasis.DIRECTED_FUNCTION_CFG_PATH,
    ]
    assert list(StaticTriggerPathWitnessUse) == [
        StaticTriggerPathWitnessUse.REACHABILITY_AUDIT_ONLY
    ]
    assert list(StaticTriggerCandidateObjectiveObligation) == [
        StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_REQUIRED,
        StaticTriggerCandidateObjectiveObligation
        .SYMBOLIC_PATH_FEASIBILITY_REMAINS_UNRESOLVED,
        StaticTriggerCandidateObjectiveObligation
        .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
        StaticTriggerCandidateObjectiveObligation
        .RUNTIME_EXECUTION_CONTEXT_REQUIRED,
        StaticTriggerCandidateObjectiveObligation
        .RELATION_PROXIMITY_REMAINS_UNRESOLVED,
        StaticTriggerCandidateObjectiveObligation
        .ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED,
    ]


def test_contract_and_single_value_schema_literals() -> None:
    schemas = [
        StaticTriggerPositionCandidate.model_json_schema(),
        StaticTriggerOrderWitness.model_json_schema(),
        StaticTriggerCaseCandidate.model_json_schema(),
        StaticTriggerCandidateProjection.model_json_schema(),
        StaticTriggerCandidateMaterialization.model_json_schema(),
    ]
    assert schemas[0]["properties"]["contract"]["const"] == (
        "phase10d_static_trigger_position_candidate_v1"
    )
    assert schemas[1]["properties"]["contract"]["const"] == (
        "phase10d_static_trigger_order_witness_v1"
    )
    assert schemas[2]["properties"]["contract"]["const"] == (
        "phase10d_static_trigger_case_candidate_v1"
    )
    assert schemas[3]["properties"]["contract"]["const"] == (
        "phase10d_static_trigger_candidate_projection_v1"
    )
    assert schemas[4]["properties"]["contract"]["const"] == (
        "phase10d_static_trigger_candidate_materialization_v1"
    )


def test_v1_semantic_schema_vocabularies_are_exactly_literal_locked() -> None:
    case_schema = StaticTriggerCaseCandidate.model_json_schema()["properties"]
    position_schema = StaticTriggerPositionCandidate.model_json_schema()[
        "properties"
    ]
    witness_schema = StaticTriggerOrderWitness.model_json_schema()["properties"]

    assert case_schema["remaining_objective_obligations"]["items"]["enum"] == [
        "runtime_execution_required",
        "symbolic_path_feasibility_remains_unresolved",
        "effective_memory_type_resolution_required",
        "runtime_execution_context_required",
        "relation_proximity_remains_unresolved",
        "additional_hardware_timing_remains_unresolved",
    ]
    assert case_schema["candidate_semantics"]["const"] == (
        "static_structural_pattern_candidate_only"
    )
    assert position_schema["candidate_semantics"]["const"] == (
        "static_structural_pattern_candidate_only"
    )
    assert witness_schema["order_basis"]["enum"] == [
        "same_basic_block_static_instruction_order",
        "directed_function_cfg_path",
    ]
    assert witness_schema["path_witness_use"]["anyOf"] == [
        {"const": "reachability_audit_only", "type": "string"},
        {"type": "null"},
    ]


def test_owned_end_to_end_has_exact_two_declared_cases(owned) -> None:
    projection = owned.projection
    assert len(projection.case_candidates) == 2
    assert sum(len(item.position_candidates) for item in projection.case_candidates) == 6
    assert sum(len(item.order_witnesses) for item in projection.case_candidates) == 4
    assert {item.case_reference_id for item in projection.case_candidates} == {
        "owned-case-a",
        "owned-case-b",
    }
    assert all(
        [position.instruction_address for position in candidate.position_candidates]
        in [
            ["0x400000", "0x400008", "0x400018"],
            ["0x400000", "0x400010", "0x400018"],
        ]
        for candidate in projection.case_candidates
    )


def test_owned_does_not_combine_or_shorten_source_cases(owned) -> None:
    sequences = {
        tuple(item.instruction_address for item in candidate.position_candidates)
        for candidate in owned.projection.case_candidates
    }
    assert ("0x400000", "0x400008", "0x400010", "0x400018") not in sequences
    assert ("0x400000", "0x400018") not in sequences


def test_mixed_catalog_skips_architecture_and_instruction_set(owned_fused) -> None:
    predicate = _predicate(StaticSemanticOperation.MEMORY_LOAD)
    riscv = _pattern(
        [[predicate]],
        architecture=Architecture.RISC_V,
        instruction_set="rv64gc",
        name="owned_synthetic_risc_v_pattern",
    )
    wrong_set = _pattern(
        [[predicate]],
        instruction_set="a32",
        name="owned_synthetic_wrong_set_pattern",
    )
    result = _materialize(owned_fused, riscv, wrong_set)
    assert result.projection.compatible_pattern_ids == []
    assert result.projection.incompatible_pattern_ids == sorted(
        [riscv.id, wrong_set.id]
    )
    assert result.projection.case_candidates == []


def test_empty_catalog_and_no_semantic_candidate_are_valid(owned_fused) -> None:
    empty = _materialize(owned_fused)
    absent = _pattern(
        [[_predicate(StaticSemanticOperation.MEMORY_STORE)]],
        name="owned_synthetic_absent_operation_pattern",
    )
    no_candidate = _materialize(owned_fused, absent)
    assert empty.projection.case_candidates == []
    assert no_candidate.projection.case_candidates == []


def test_exact_attributes_additional_attributes_and_broad_predicate(
    owned_fused,
) -> None:
    exact = _predicate(
        StaticSemanticOperation.MEMORY_BARRIER,
        attributes=[
            _attribute(StaticSemanticAttributeName.BARRIER_KIND, "dsb")
        ],
    )
    broad = _predicate(StaticSemanticOperation.MEMORY_BARRIER)
    mismatch = _predicate(
        StaticSemanticOperation.MEMORY_BARRIER,
        attributes=[
            _attribute(StaticSemanticAttributeName.BARRIER_KIND, "dmb")
        ],
    )
    assert len(_materialize(owned_fused, _pattern([[exact]])).projection.case_candidates) == 1
    assert len(_materialize(owned_fused, _pattern([[broad]])).projection.case_candidates) == 1
    assert _materialize(owned_fused, _pattern([[mismatch]])).projection.case_candidates == []


def test_or_alternatives_are_all_evaluated_independently(owned_fused) -> None:
    exact = _predicate(
        StaticSemanticOperation.SYSTEM_REGISTER_READ,
        attributes=[
            _attribute(StaticSemanticAttributeName.SYSTEM_REGISTER, "par_el1")
        ],
    )
    broad = _predicate(StaticSemanticOperation.SYSTEM_REGISTER_READ)
    result = _materialize(owned_fused, _pattern([[exact, broad]])).projection
    assert len(result.case_candidates) == 2
    assert len({item.position_candidates[0].source_predicate_id for item in result.case_candidates}) == 2


def test_one_predicate_retains_two_matching_facts() -> None:
    first = _fact(
        index=1,
        operation=StaticSemanticOperation.MEMORY_LOAD,
        address="0x500000",
        block="0x500000",
    )
    second = _fact(
        index=2,
        operation=StaticSemanticOperation.MEMORY_LOAD,
        address="0x500004",
        block="0x500000",
    )
    fused = _synthetic_fused(
        facts=[first, second],
        blocks_by_function={"0x500000": ["0x500000"]},
        edges_by_function={},
    )
    predicate = _predicate(StaticSemanticOperation.MEMORY_LOAD)
    candidates = _materialize(
        fused, _pattern([[predicate]])
    ).projection.case_candidates

    assert len(candidates) == 2
    positions = [candidate.position_candidates[0] for candidate in candidates]
    assert {position.source_predicate_id for position in positions} == {
        predicate.id
    }
    assert {position.source_semantic_fact_ids[0] for position in positions} == {
        first.id,
        second.id,
    }
    assert len({position.id for position in positions}) == 2


def test_unselected_or_alternative_obligation_does_not_contaminate_candidate() -> None:
    fact = _fact(
        index=1,
        operation=StaticSemanticOperation.MEMORY_LOAD,
        address="0x500000",
        block="0x500000",
    )
    fused = _synthetic_fused(
        facts=[fact],
        blocks_by_function={"0x500000": ["0x500000"]},
        edges_by_function={},
    )
    without_extra_obligation = _predicate(
        StaticSemanticOperation.MEMORY_LOAD
    )
    with_extra_obligation = _predicate(
        StaticSemanticOperation.MEMORY_LOAD,
        contexts=["privileged_aarch64"],
        requirements=[
            StaticTriggerObjectiveRequirement.RUNTIME_EXECUTION_CONTEXT_REQUIRED
        ],
    )
    candidates = _materialize(
        fused,
        _pattern([[without_extra_obligation, with_extra_obligation]]),
    ).projection.case_candidates
    by_predicate = {
        candidate.position_candidates[0].source_predicate_id: candidate
        for candidate in candidates
    }

    assert set(by_predicate) == {
        without_extra_obligation.id,
        with_extra_obligation.id,
    }
    assert by_predicate[
        without_extra_obligation.id
    ].remaining_objective_obligations == [
        StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_REQUIRED
    ]
    assert set(
        by_predicate[with_extra_obligation.id].remaining_objective_obligations
    ) == {
        StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_REQUIRED,
        StaticTriggerCandidateObjectiveObligation
        .RUNTIME_EXECUTION_CONTEXT_REQUIRED,
    }


def test_same_block_forward_order_and_reverse_rejection() -> None:
    load = _fact(index=1, operation=StaticSemanticOperation.MEMORY_LOAD, address="0x500000", block="0x500000")
    store = _fact(index=2, operation=StaticSemanticOperation.MEMORY_STORE, address="0x500004", block="0x500000")
    fused = _synthetic_fused(
        facts=[load, store],
        blocks_by_function={"0x500000": ["0x500000"]},
        edges_by_function={},
    )
    forward = _pattern([[ _predicate(StaticSemanticOperation.MEMORY_LOAD)], [_predicate(StaticSemanticOperation.MEMORY_STORE)]])
    reverse = _pattern([[ _predicate(StaticSemanticOperation.MEMORY_STORE)], [_predicate(StaticSemanticOperation.MEMORY_LOAD)]], name="owned_synthetic_reverse_pattern")
    candidate = _materialize(fused, forward).projection.case_candidates[0]
    assert candidate.order_witnesses[0].order_basis is StaticTriggerOrderBasis.SAME_BASIC_BLOCK_STATIC_INSTRUCTION_ORDER
    assert candidate.order_witnesses[0].witness_cfg_relation_ids == []
    assert _materialize(fused, reverse).projection.case_candidates == []


def test_self_loop_cannot_make_reverse_same_block_order() -> None:
    first = _fact(index=1, operation=StaticSemanticOperation.MEMORY_LOAD, address="0x500000", block="0x500000")
    second = _fact(index=2, operation=StaticSemanticOperation.MEMORY_STORE, address="0x500004", block="0x500000")
    fused = _synthetic_fused(
        facts=[first, second],
        blocks_by_function={"0x500000": ["0x500000"]},
        edges_by_function={"0x500000": [("0x500000", "0x500000")]},
    )
    reverse = _pattern([[ _predicate(StaticSemanticOperation.MEMORY_STORE)], [_predicate(StaticSemanticOperation.MEMORY_LOAD)]])
    assert _materialize(fused, reverse).projection.case_candidates == []


def test_standalone_case_requires_each_exact_adjacent_witness_pair(owned) -> None:
    valid_payload = owned.projection.case_candidates[0].model_dump(mode="json")
    StaticTriggerCaseCandidate.model_validate(valid_payload)

    duplicate = json.loads(json.dumps(valid_payload["order_witnesses"][0]))
    duplicate["witness_cfg_relation_ids"] = [
        f"static-fused-behavior-relation:{'d' * 64}"
    ]
    _rehash(duplicate, static_trigger_order_witness_id)
    valid_payload["order_witnesses"] = [
        valid_payload["order_witnesses"][0],
        duplicate,
    ]
    _rehash(valid_payload, static_trigger_case_candidate_id)

    with pytest.raises(
        ValidationError, match="exact adjacent witness coverage mismatch"
    ):
        StaticTriggerCaseCandidate.model_validate(valid_payload)


def test_same_fact_reuse_is_rejected() -> None:
    fact = _fact(index=1, operation=StaticSemanticOperation.MEMORY_LOAD, address="0x500000", block="0x500000")
    fused = _synthetic_fused(facts=[fact], blocks_by_function={"0x500000": ["0x500000"]}, edges_by_function={})
    pattern = _pattern([[ _predicate(StaticSemanticOperation.MEMORY_LOAD)], [_predicate(StaticSemanticOperation.MEMORY_LOAD)]])
    assert _materialize(fused, pattern).projection.case_candidates == []


def test_cross_function_and_address_order_without_cfg_are_rejected() -> None:
    first = _fact(index=1, operation=StaticSemanticOperation.MEMORY_LOAD, address="0x500000", block="0x500000", function="0x500000")
    other = _fact(index=2, operation=StaticSemanticOperation.MEMORY_STORE, address="0x600000", block="0x600000", function="0x600000")
    fused = _synthetic_fused(
        facts=[first, other],
        blocks_by_function={"0x500000": ["0x500000"], "0x600000": ["0x600000"]},
        edges_by_function={},
    )
    pattern = _pattern([[ _predicate(StaticSemanticOperation.MEMORY_LOAD)], [_predicate(StaticSemanticOperation.MEMORY_STORE)]])
    assert _materialize(fused, pattern).projection.case_candidates == []


def test_same_function_address_order_without_cfg_is_rejected() -> None:
    first = _fact(
        index=1,
        operation=StaticSemanticOperation.MEMORY_LOAD,
        address="0x500000",
        block="0x500000",
    )
    second = _fact(
        index=2,
        operation=StaticSemanticOperation.MEMORY_STORE,
        address="0x500100",
        block="0x500100",
    )
    fused = _synthetic_fused(
        facts=[first, second],
        blocks_by_function={"0x500000": ["0x500000", "0x500100"]},
        edges_by_function={},
    )
    pattern = _pattern(
        [[_predicate(StaticSemanticOperation.MEMORY_LOAD)],
         [_predicate(StaticSemanticOperation.MEMORY_STORE)]]
    )
    assert _materialize(fused, pattern).projection.case_candidates == []


def test_reverse_numeric_address_with_cfg_path_is_accepted() -> None:
    first = _fact(index=1, operation=StaticSemanticOperation.MEMORY_LOAD, address="0x500100", block="0x500100")
    second = _fact(index=2, operation=StaticSemanticOperation.MEMORY_STORE, address="0x500000", block="0x500000")
    fused = _synthetic_fused(
        facts=[first, second],
        blocks_by_function={"0x500000": ["0x500000", "0x500100"]},
        edges_by_function={"0x500000": [("0x500100", "0x500000")]},
    )
    pattern = _pattern([[ _predicate(StaticSemanticOperation.MEMORY_LOAD)], [_predicate(StaticSemanticOperation.MEMORY_STORE)]])
    candidate = _materialize(fused, pattern).projection.case_candidates[0]
    assert candidate.order_witnesses[0].order_basis is StaticTriggerOrderBasis.DIRECTED_FUNCTION_CFG_PATH


def test_none_block_rejected_for_multiple_positions_but_allowed_for_single() -> None:
    first = _fact(index=1, operation=StaticSemanticOperation.MEMORY_LOAD, address="0x500000", block=None)
    second = _fact(index=2, operation=StaticSemanticOperation.MEMORY_STORE, address="0x500004", block="0x500000")
    fused = _synthetic_fused(
        facts=[first, second],
        blocks_by_function={"0x500000": ["0x500000"]},
        edges_by_function={},
    )
    multi = _pattern([[ _predicate(StaticSemanticOperation.MEMORY_LOAD)], [_predicate(StaticSemanticOperation.MEMORY_STORE)]])
    single = _pattern([[ _predicate(StaticSemanticOperation.MEMORY_LOAD)]], name="owned_synthetic_single_pattern")
    assert _materialize(fused, multi).projection.case_candidates == []
    assert len(_materialize(fused, single).projection.case_candidates) == 1


def test_unscoped_shared_semantic_block_can_use_static_order() -> None:
    first = _fact(index=1, operation=StaticSemanticOperation.MEMORY_LOAD, address="0x700000", block="0x700000", function=None)
    second = _fact(index=2, operation=StaticSemanticOperation.MEMORY_STORE, address="0x700004", block="0x700000", function=None)
    fused = _synthetic_fused(facts=[first, second], blocks_by_function={}, edges_by_function={})
    pattern = _pattern([[ _predicate(StaticSemanticOperation.MEMORY_LOAD)], [_predicate(StaticSemanticOperation.MEMORY_STORE)]])
    candidate = _materialize(fused, pattern).projection.case_candidates[0]
    assert candidate.function_address is None
    assert candidate.order_witnesses[0].order_basis is StaticTriggerOrderBasis.SAME_BASIC_BLOCK_STATIC_INSTRUCTION_ORDER


def test_unscoped_facts_do_not_gain_scoped_cfg_support_by_raw_address() -> None:
    first = _fact(
        index=1,
        operation=StaticSemanticOperation.MEMORY_LOAD,
        address="0x500010",
        block="0x500010",
        function=None,
    )
    second = _fact(
        index=2,
        operation=StaticSemanticOperation.MEMORY_STORE,
        address="0x500020",
        block="0x500020",
        function=None,
    )
    fused = _synthetic_fused(
        facts=[first, second],
        blocks_by_function={"0x500000": ["0x500010", "0x500020"]},
        edges_by_function={"0x500000": [("0x500010", "0x500020")]},
    )
    node_by_id = {node.id: node for node in fused.projection.nodes}
    fact_node_by_source_id = {
        node.semantic_source_fact_ids[0]: node
        for node in fused.projection.nodes
        if node.kind is StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT
    }
    containing_block_by_fact_id = {
        relation.target_node_id: node_by_id[relation.source_node_id]
        for relation in fused.projection.relations
        if relation.relation_kind
        is StaticFusedBehaviorRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT
    }
    unscoped_block = containing_block_by_fact_id[
        fact_node_by_source_id[first.id].id
    ]
    scoped_block = next(
        node
        for node in fused.projection.nodes
        if node.kind is StaticFusedBehaviorNodeKind.BASIC_BLOCK
        and node.function_address == "0x500000"
        and node.basic_block_address == "0x500010"
    )

    assert unscoped_block.function_address is None
    assert unscoped_block.basic_block_address == scoped_block.basic_block_address
    assert unscoped_block.id != scoped_block.id
    pattern = _pattern(
        [
            [_predicate(StaticSemanticOperation.MEMORY_LOAD)],
            [_predicate(StaticSemanticOperation.MEMORY_STORE)],
        ]
    )
    assert _materialize(fused, pattern).projection.case_candidates == []


def test_canonical_shortest_cfg_path_is_input_order_independent() -> None:
    source = _fact(index=1, operation=StaticSemanticOperation.MEMORY_LOAD, address="0x500000", block="0x500000")
    target = _fact(index=2, operation=StaticSemanticOperation.MEMORY_STORE, address="0x500030", block="0x500030")
    blocks = ["0x500000", "0x500010", "0x500020", "0x500030"]
    edges = [("0x500000", "0x500020"), ("0x500020", "0x500030"), ("0x500000", "0x500010"), ("0x500010", "0x500030")]
    first = _synthetic_fused(facts=[source, target], blocks_by_function={"0x500000": blocks}, edges_by_function={"0x500000": edges})
    second = _synthetic_fused(facts=[target, source], blocks_by_function={"0x500000": list(reversed(blocks))}, edges_by_function={"0x500000": list(reversed(edges))})
    pattern = _pattern([[ _predicate(StaticSemanticOperation.MEMORY_LOAD)], [_predicate(StaticSemanticOperation.MEMORY_STORE)]])
    one = _materialize(first, pattern)
    two = _materialize(second, pattern)
    assert one == two
    witness = one.projection.case_candidates[0].order_witnesses[0]
    block_addresses = [
        first.projection.nodes[[node.id for node in first.projection.nodes].index(block_id)].basic_block_address
        for block_id in witness.witness_basic_block_node_ids
    ]
    assert block_addresses == ["0x500000", "0x500010", "0x500030"]


def test_unresolved_requirements_are_propagated_without_satisfaction() -> None:
    load = _fact(index=1, operation=StaticSemanticOperation.MEMORY_LOAD, address="0x500000", block="0x500000")
    fused = _synthetic_fused(facts=[load], blocks_by_function={"0x500000": ["0x500000"]}, edges_by_function={})
    predicate = _predicate(
        StaticSemanticOperation.MEMORY_LOAD,
        memory_types=["device"],
        contexts=["privileged_aarch64"],
        requirements=[
            StaticTriggerObjectiveRequirement.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
            StaticTriggerObjectiveRequirement.RUNTIME_EXECUTION_CONTEXT_REQUIRED,
        ],
    )
    pattern = _pattern(
        [[predicate]],
        pattern_requirements=[StaticTriggerObjectiveRequirement.ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED],
        case_requirements=[StaticTriggerObjectiveRequirement.RELATION_PROXIMITY_REMAINS_UNRESOLVED],
        relation=True,
    )
    obligations = set(_materialize(fused, pattern).projection.case_candidates[0].remaining_objective_obligations)
    assert obligations == {
        StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_REQUIRED,
        StaticTriggerCandidateObjectiveObligation.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
        StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_CONTEXT_REQUIRED,
        StaticTriggerCandidateObjectiveObligation.RELATION_PROXIMITY_REMAINS_UNRESOLVED,
        StaticTriggerCandidateObjectiveObligation.ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED,
    }


def test_qualitative_proximity_does_not_reject_a_long_cfg_path() -> None:
    first = _fact(
        index=1,
        operation=StaticSemanticOperation.MEMORY_LOAD,
        address="0x500000",
        block="0x500000",
    )
    second = _fact(
        index=2,
        operation=StaticSemanticOperation.MEMORY_STORE,
        address="0x500030",
        block="0x500030",
    )
    fused = _synthetic_fused(
        facts=[first, second],
        blocks_by_function={
            "0x500000": [
                "0x500000", "0x500010", "0x500020", "0x500030"
            ]
        },
        edges_by_function={
            "0x500000": [
                ("0x500000", "0x500010"),
                ("0x500010", "0x500020"),
                ("0x500020", "0x500030"),
            ]
        },
    )
    pattern = _pattern(
        [[_predicate(StaticSemanticOperation.MEMORY_LOAD)],
         [_predicate(StaticSemanticOperation.MEMORY_STORE)]],
        case_requirements=[
            StaticTriggerObjectiveRequirement
            .RELATION_PROXIMITY_REMAINS_UNRESOLVED
        ],
        relation=True,
    )
    candidate = _materialize(fused, pattern).projection.case_candidates[0]
    assert len(candidate.order_witnesses[0].witness_basic_block_node_ids) == 4
    assert (
        StaticTriggerCandidateObjectiveObligation
        .RELATION_PROXIMITY_REMAINS_UNRESOLVED
        in candidate.remaining_objective_obligations
    )


def test_cfg_path_adds_symbolic_feasibility_obligation(owned) -> None:
    expected = {
        StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_REQUIRED,
        StaticTriggerCandidateObjectiveObligation.SYMBOLIC_PATH_FEASIBILITY_REMAINS_UNRESOLVED,
    }
    assert all(set(item.remaining_objective_obligations) == expected for item in owned.projection.case_candidates)


def test_risc_v_contract_uses_same_generic_matcher() -> None:
    load = _fact(index=1, operation=StaticSemanticOperation.MEMORY_LOAD, address="0x800000", block="0x800000", architecture=Architecture.RISC_V, instruction_set="rv64gc")
    barrier = _fact(index=2, operation=StaticSemanticOperation.MEMORY_BARRIER, address="0x800004", block="0x800000", architecture=Architecture.RISC_V, instruction_set="rv64gc")
    fused = _synthetic_fused(facts=[load, barrier], blocks_by_function={"0x500000": ["0x800000"]}, edges_by_function={}, architecture=Architecture.RISC_V, instruction_set="rv64gc")
    pattern = _pattern([[ _predicate(StaticSemanticOperation.MEMORY_LOAD)], [_predicate(StaticSemanticOperation.MEMORY_BARRIER)]], architecture=Architecture.RISC_V, instruction_set="rv64gc", name="owned_synthetic_risc_v_contract_pattern")
    assert len(_materialize(fused, pattern).projection.case_candidates) == 1


def _rehash(payload: dict, function) -> None:
    payload["id"] = function({key: value for key, value in payload.items() if key != "id"})


def _rehash_case_and_projection(projection: dict, case: dict) -> None:
    _rehash(case, static_trigger_case_candidate_id)
    _rehash(projection, static_trigger_candidate_projection_id)


def test_rehashed_foreign_pattern_validates_projection_but_not_materialization(owned) -> None:
    payload = owned.model_dump(mode="json")
    projection = payload["projection"]
    foreign = f"static-trigger-pattern:{'f' * 64}"
    original = projection["compatible_pattern_ids"][0]
    for case in projection["case_candidates"]:
        case["source_pattern_id"] = foreign
        for position in case["position_candidates"]:
            position["source_pattern_id"] = foreign
            _rehash(position, static_trigger_position_candidate_id)
        position_ids = {
            item["position_index"]: item["id"]
            for item in case["position_candidates"]
        }
        for witness in case["order_witnesses"]:
            witness["source_position_candidate_id"] = position_ids[
                witness["from_position_index"]
            ]
            witness["target_position_candidate_id"] = position_ids[
                witness["to_position_index"]
            ]
            _rehash(witness, static_trigger_order_witness_id)
        _rehash(case, static_trigger_case_candidate_id)
    projection["compatible_pattern_ids"] = [
        foreign if item == original else item
        for item in projection["compatible_pattern_ids"]
    ]
    _rehash(projection, static_trigger_candidate_projection_id)
    StaticTriggerCandidateProjection.model_validate(projection)
    _rehash(payload, static_trigger_candidate_materialization_id)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticTriggerCandidateMaterialization.model_validate(payload)


@pytest.mark.parametrize("foreign_target", ["fact", "cfg_relation"])
def test_rehashed_foreign_fused_provenance_is_rejected_authoritatively(owned, foreign_target: str) -> None:
    payload = owned.model_dump(mode="json")
    projection = payload["projection"]
    case = projection["case_candidates"][0]
    if foreign_target == "fact":
        position = case["position_candidates"][0]
        position["source_fused_fact_node_id"] = f"static-fused-behavior-node:{'e' * 64}"
        _rehash(position, static_trigger_position_candidate_id)
        for witness in case["order_witnesses"]:
            if witness["from_position_index"] == position["position_index"]:
                witness["source_position_candidate_id"] = position["id"]
                _rehash(witness, static_trigger_order_witness_id)
    else:
        witness = case["order_witnesses"][0]
        witness["witness_cfg_relation_ids"][0] = f"static-fused-behavior-relation:{'e' * 64}"
        _rehash(witness, static_trigger_order_witness_id)
    _rehash_case_and_projection(projection, case)
    StaticTriggerCandidateProjection.model_validate(projection)
    _rehash(payload, static_trigger_candidate_materialization_id)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticTriggerCandidateMaterialization.model_validate(payload)


def test_valid_alternate_fused_snapshot_is_rejected_by_reprojection(owned) -> None:
    fact = _fact(
        index=7,
        operation=StaticSemanticOperation.MEMORY_LOAD,
        address="0x500000",
        block="0x500000",
    )
    alternate = _synthetic_fused(
        facts=[fact],
        blocks_by_function={"0x500000": ["0x500000"]},
        edges_by_function={},
    )
    payload = owned.model_dump(mode="json")
    payload["source_fused_graph_materialization_id"] = alternate.id
    payload["source_fused_graph_materialization_snapshot"] = (
        alternate.model_dump(mode="json")
    )
    _rehash(payload, static_trigger_candidate_materialization_id)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticTriggerCandidateMaterialization.model_validate(payload)


def test_valid_alternate_catalog_snapshot_is_rejected_by_reprojection(owned) -> None:
    alternate = StaticTriggerPatternCatalog.create(patterns=[])
    payload = owned.model_dump(mode="json")
    payload["source_pattern_catalog_id"] = alternate.id
    payload["source_pattern_catalog_snapshot"] = alternate.model_dump(
        mode="json"
    )
    _rehash(payload, static_trigger_candidate_materialization_id)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticTriggerCandidateMaterialization.model_validate(payload)


def test_retained_ids_diagnostics_and_source_snapshot_tampering_fail(owned) -> None:
    for target in ("projection", "materialization", "diagnostics", "source"):
        payload = owned.model_dump(mode="json")
        if target == "projection":
            payload["projection"]["id"] = "static-trigger-candidate-projection:bad"
        elif target == "materialization":
            payload["id"] = "static-trigger-candidate-materialization:bad"
        elif target == "diagnostics":
            payload["projection"]["diagnostic_codes"][0] = "case_candidate_count:999"
            _rehash(payload["projection"], static_trigger_candidate_projection_id)
            _rehash(payload, static_trigger_candidate_materialization_id)
        else:
            payload["source_pattern_catalog_snapshot"]["id"] = "static-trigger-pattern-catalog:bad"
        with pytest.raises((ValidationError, ValueError)):
            StaticTriggerCandidateMaterialization.model_validate(payload)


@pytest.mark.parametrize(
    "target",
    ["position", "witness", "case", "projection", "materialization"],
)
def test_every_retained_candidate_id_fails_closed(owned, target: str) -> None:
    payload = owned.model_dump(mode="json")
    case = payload["projection"]["case_candidates"][0]
    if target == "position":
        case["position_candidates"][0]["id"] = (
            "static-trigger-position-candidate:bad"
        )
    elif target == "witness":
        case["order_witnesses"][0]["id"] = (
            "static-trigger-order-witness:bad"
        )
    elif target == "case":
        case["id"] = "static-trigger-case-candidate:bad"
    elif target == "projection":
        payload["projection"]["id"] = (
            "static-trigger-candidate-projection:bad"
        )
    else:
        payload["id"] = "static-trigger-candidate-materialization:bad"
    with pytest.raises((ValidationError, ValueError)):
        StaticTriggerCandidateMaterialization.model_validate(payload)


def test_caller_mutation_does_not_change_materialization(owned_fused, owned_pattern) -> None:
    mutable_fused = type(owned_fused).model_validate(
        owned_fused.model_dump(mode="json")
    )
    catalog = StaticTriggerPatternCatalog.create(patterns=[owned_pattern])
    result = project_static_trigger_candidates(mutable_fused, catalog)
    before = result.model_dump_json()
    catalog.patterns.clear()
    mutable_fused.projection.nodes.clear()
    assert result.model_dump_json() == before


def test_owned_is_deterministic_across_ten_runs(owned_fused, owned_pattern) -> None:
    outputs = [
        _materialize(owned_fused, owned_pattern)
        for _ in range(10)
    ]
    assert len({item.projection.id for item in outputs}) == 1
    assert len({item.id for item in outputs}) == 1
    assert len(
        {
            hashlib.sha256(
                json.dumps(
                    item.model_dump(mode="json"),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            for item in outputs
        }
    ) == 1


def test_catalog_pattern_order_is_canonical(owned_fused, owned_pattern) -> None:
    incompatible = _pattern(
        [[_predicate(StaticSemanticOperation.MEMORY_LOAD)]],
        architecture=Architecture.RISC_V,
        instruction_set="rv64gc",
        name="owned_synthetic_catalog_order_pattern",
    )
    first = _materialize(owned_fused, owned_pattern, incompatible)
    second = _materialize(owned_fused, incompatible, owned_pattern)
    assert first == second


def test_core_dependency_firewall() -> None:
    forbidden = {
        "angr",
        "capstone",
        "aarch64_static_semantic_decoder",
        "aarch64_static_program_structure_extractor",
        "hardware_trigger",
        "knowledge",
        "reasoning",
        "runtime",
        "verification",
    }
    for filename in (
        "static_trigger_candidate_models.py",
        "static_trigger_candidate_matching.py",
    ):
        tree = ast.parse((ROOT / "src/chipchain/analysis" / filename).read_text())
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        assert not any(any(part in module for part in forbidden) for module in imports)


def test_models_expose_no_outcome_fields() -> None:
    forbidden = {"matched", "triggered", "triggerable", "vulnerable", "verified", "confidence", "probability", "score", "attack_chain"}
    schemas = [
        StaticTriggerCandidateProjection.model_json_schema(),
        StaticTriggerCandidateMaterialization.model_json_schema(),
    ]
    for schema in schemas:
        assert forbidden.isdisjoint(json.dumps(schema).lower().split('"'))
    projection_fields = StaticTriggerCandidateProjection.model_fields
    case_fields = StaticTriggerCaseCandidate.model_fields
    assert "hardware_reference_ids" not in projection_fields
    assert "hardware_reference_ids" not in case_fields
