"""Phase 10D Step 8B-2D1 typed static projection contract tests."""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.analysis import (
    PHASE10D_A_PROFILE_STATIC_BEHAVIOR_PROJECTION_MATERIALIZATION_CONTRACT,
    PHASE10D_STATIC_BEHAVIOR_ANALYSIS_PROJECTION_CONTRACT,
    PHASE10D_STATIC_BEHAVIOR_GRAPH_PROJECTION_CONTRACT,
    PHASE10D_STATIC_PATTERN_BINDING_PROJECTION_CONTRACT,
    AProfileStaticBehaviorProjectionMaterialization,
    ProgramArtifact,
    StaticAssertionClass,
    StaticBehaviorAnalysisProjection,
    StaticBehaviorGraphProjection,
    StaticBehaviorNodeKind,
    StaticBehaviorProjectionScope,
    StaticBehaviorRelationKind,
    StaticPatternBindingKind,
    StaticPatternBindingProjection,
    StaticPatternBindingSemantics,
    StaticPatternOrderBasis,
    StaticPatternPathWitnessUse,
    StaticObjectiveObligation,
    a_profile_static_behavior_projection_materialization_id,
    project_static_behavior_analysis,
    static_behavior_analysis_projection_id,
    static_behavior_graph_projection_id,
    static_behavior_node_id,
    static_behavior_relation_id,
    static_pattern_binding_projection_id,
    static_pattern_binding_record_id,
)
from chipchain.hardware_trigger import (
    AProfileStaticCfgEdge,
    AProfileStaticFunctionCfgSnapshot,
    AProfileStaticInstructionSetState,
    AProfileStaticPredicateCandidate,
    AProfileStaticSemanticExtractionPlan,
    AProfileStaticSemanticExtractionResult,
    AProfileStaticSemanticInstructionFact,
    AProfileSystemRegister,
    AngrAProfileStaticCaseMaterializer,
    RemainingObjectiveObligation,
    StaticEffectiveMemoryTypeResolution,
    StaticFactScope,
    assemble_static_case_order_candidates,
)
from chipchain.hardware_trigger.a_profile_semantic_models import (
    AProfileSemanticEventKind,
)
from chipchain.models import Architecture


ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_a_profile_static_semantic_extraction_plan_v1.json"
)
FIXTURE = (
    ROOT
    / "tests/fixtures/phase10d/a_profile_static_semantic_a64/"
    "a_profile_static_semantic_a64.elf"
)


@pytest.fixture(scope="module")
def plan() -> AProfileStaticSemanticExtractionPlan:
    return AProfileStaticSemanticExtractionPlan.model_validate_json(
        PLAN_PATH.read_bytes()
    )


def _entry(plan, *, case_id, position, event_kind):
    return next(
        item
        for item in plan.predicate_entries
        if (
            item.case_id,
            item.position_index,
            item.event_kind,
        )
        == (case_id, position, event_kind)
    )


def _fact(
    *,
    event_kind: AProfileSemanticEventKind,
    address: str,
    block: str,
    function: str = "0x0000000000401000",
) -> AProfileStaticSemanticInstructionFact:
    words = {
        AProfileSemanticEventKind.MEMORY_LOAD: "0xf9400020",
        AProfileSemanticEventKind.STORE_EXCLUSIVE: "0xc8007c41",
        AProfileSemanticEventKind.SYSTEM_REGISTER_READ: "0xd5387400",
    }
    is_load = event_kind is AProfileSemanticEventKind.MEMORY_LOAD
    is_system_read = (
        event_kind is AProfileSemanticEventKind.SYSTEM_REGISTER_READ
    )
    return AProfileStaticSemanticInstructionFact.create(
        artifact_id="artifact:owned-synthetic-static-projection",
        artifact_sha256="a" * 64,
        architecture=Architecture.ARM,
        architecture_profile="a_profile",
        instruction_set_state=AProfileStaticInstructionSetState.AARCH64,
        instruction_address=address,
        instruction_word=words[event_kind],
        instruction_size=4,
        basic_block_address=block,
        function_address=function,
        function_name="owned_static_projection_function",
        event_kind=event_kind,
        system_register=(
            AProfileSystemRegister.PAR_EL1 if is_system_read else None
        ),
        memory_type_resolution=(
            StaticEffectiveMemoryTypeResolution
            .REQUIRES_OBJECTIVE_TRANSLATION_CONTEXT
            if is_load
            else StaticEffectiveMemoryTypeResolution.NOT_APPLICABLE
        ),
        static_fact_scope=(
            StaticFactScope.DECODED_ARTIFACT_INSTRUCTION_SEMANTICS_ONLY
        ),
    )


def _synthetic_source(
    plan: AProfileStaticSemanticExtractionPlan,
    *,
    include_unprojected_fact: bool = False,
):
    first = _fact(
        event_kind=AProfileSemanticEventKind.STORE_EXCLUSIVE,
        address="0x0000000000401010",
        block="0x0000000000401000",
    )
    second = _fact(
        event_kind=AProfileSemanticEventKind.MEMORY_LOAD,
        address="0x0000000000402010",
        block="0x0000000000402000",
    )
    facts = [first, second]
    if include_unprojected_fact:
        facts.append(
            _fact(
                event_kind=AProfileSemanticEventKind.SYSTEM_REGISTER_READ,
                address="0x0000000000500010",
                block="0x0000000000500000",
                function="0x0000000000500000",
            )
        )
    candidates = [
        AProfileStaticPredicateCandidate.create(
            extraction_plan=plan,
            predicate_entry=_entry(
                plan,
                case_id="case_a",
                position=1,
                event_kind=first.event_kind,
            ),
            static_instruction_fact=first,
        ),
        AProfileStaticPredicateCandidate.create(
            extraction_plan=plan,
            predicate_entry=_entry(
                plan,
                case_id="case_a",
                position=2,
                event_kind=second.event_kind,
            ),
            static_instruction_fact=second,
        ),
    ]
    extraction = AProfileStaticSemanticExtractionResult.create(
        artifact_id=first.artifact_id,
        artifact_sha256=first.artifact_sha256,
        extraction_plan=plan,
        instruction_facts=facts,
        predicate_candidates=candidates,
    )
    cfg = AProfileStaticFunctionCfgSnapshot.create(
        extraction_result=extraction,
        function_address=first.function_address,
        function_name=first.function_name,
        basic_block_addresses=[
            first.basic_block_address,
            second.basic_block_address,
        ],
        directed_edges=[
            AProfileStaticCfgEdge(
                source_basic_block_address=first.basic_block_address,
                target_basic_block_address=second.basic_block_address,
            )
        ],
    )
    return assemble_static_case_order_candidates(extraction, [cfg])


@pytest.fixture()
def materialization(
    plan,
) -> AProfileStaticBehaviorProjectionMaterialization:
    return project_static_behavior_analysis(_synthetic_source(plan))


@pytest.fixture()
def projection(
    materialization: AProfileStaticBehaviorProjectionMaterialization,
) -> StaticBehaviorAnalysisProjection:
    return materialization.projection


def _recompute(payload: dict, field: str, id_function) -> None:
    payload[field] = id_function(
        {key: value for key, value in payload.items() if key != field}
    )


def _recompute_top(payload: dict) -> None:
    _recompute(payload, "id", static_behavior_analysis_projection_id)


def _recompute_graph(payload: dict) -> None:
    _recompute(payload["program_graph"], "id", static_behavior_graph_projection_id)
    _recompute_top(payload)


def _recompute_materialization(payload: dict) -> None:
    _recompute(
        payload,
        "id",
        a_profile_static_behavior_projection_materialization_id,
    )


def _recompute_pattern(payload: dict) -> None:
    _recompute(
        payload["pattern_bindings"],
        "id",
        static_pattern_binding_projection_id,
    )
    _recompute_top(payload)


def _replace_graph_node_id(
    payload: dict, *, old_id: str, new_id: str
) -> None:
    for relation in payload["program_graph"]["relations"]:
        changed = False
        if relation["source_node_id"] == old_id:
            relation["source_node_id"] = new_id
            changed = True
        if relation["target_node_id"] == old_id:
            relation["target_node_id"] = new_id
            changed = True
        if changed:
            _recompute(relation, "id", static_behavior_relation_id)


def test_exact_contract_versions_and_closed_vocabulary() -> None:
    assert (
        PHASE10D_A_PROFILE_STATIC_BEHAVIOR_PROJECTION_MATERIALIZATION_CONTRACT
        == "phase10d_a_profile_static_behavior_projection_materialization_v1"
    )
    assert PHASE10D_STATIC_BEHAVIOR_GRAPH_PROJECTION_CONTRACT == (
        "phase10d_static_behavior_graph_projection_v1"
    )
    assert PHASE10D_STATIC_PATTERN_BINDING_PROJECTION_CONTRACT == (
        "phase10d_static_pattern_binding_projection_v1"
    )
    assert PHASE10D_STATIC_BEHAVIOR_ANALYSIS_PROJECTION_CONTRACT == (
        "phase10d_static_behavior_analysis_projection_v1"
    )
    assert list(StaticAssertionClass) == [
        StaticAssertionClass.OBJECTIVE_STATIC_FACT,
        StaticAssertionClass.OBJECTIVE_STRUCTURAL_RELATION,
        StaticAssertionClass.DETERMINISTIC_PATTERN_CANDIDATE,
    ]
    assert list(StaticBehaviorNodeKind) == [
        StaticBehaviorNodeKind.FUNCTION,
        StaticBehaviorNodeKind.BASIC_BLOCK,
        StaticBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT,
    ]
    assert list(StaticBehaviorRelationKind) == [
        StaticBehaviorRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK,
        StaticBehaviorRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT,
        StaticBehaviorRelationKind.CFG_SUCCESSOR,
    ]
    assert list(StaticBehaviorProjectionScope) == [
        StaticBehaviorProjectionScope.BINARY_STATIC_PROGRAM_ANALYSIS
    ]


def test_shared_model_source_has_no_architecture_adapter_dependency() -> None:
    path = ROOT / "src/chipchain/analysis/static_behavior_models.py"
    text = path.read_text(encoding="utf-8")
    assert "chipchain.hardware_trigger" not in text
    tree = ast.parse(text)
    production_identifiers = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    } | {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.ClassDef, ast.FunctionDef))
    }
    assert not any(
        value.startswith(("AProfile", "Arm", "Cortex"))
        for value in production_identifiers
    )


def test_shared_projection_schema_has_no_a_profile_source_model() -> None:
    schema = str(StaticBehaviorAnalysisProjection.model_json_schema()).lower()
    for forbidden in (
        "aprofilestaticcaseassemblyresult",
        "aprofilestaticsemantic",
        "cortex",
        "cve",
        "erratum",
    ):
        assert forbidden not in schema


def test_generic_projection_constructs_without_architecture_source_object() -> None:
    graph = StaticBehaviorGraphProjection.create(
        contract=PHASE10D_STATIC_BEHAVIOR_GRAPH_PROJECTION_CONTRACT,
        architecture=Architecture.RISC_V,
        artifact_id="artifact:generic-static-input",
        artifact_sha256="d" * 64,
        source_static_analysis_result_id="generic-analysis-result",
        nodes=[],
        relations=[],
        projection_scope=(
            StaticBehaviorProjectionScope.BINARY_STATIC_PROGRAM_ANALYSIS
        ),
        unprojected_nonpredicate_fact_count=0,
        diagnostic_codes=[
            "basic_block_node_count:0",
            "cfg_successor_relation_count:0",
            "function_node_count:0",
            "semantic_fact_node_count:0",
            "unprojected_nonpredicate_fact_count:0",
        ],
    )
    bindings = StaticPatternBindingProjection.create(
        contract=PHASE10D_STATIC_PATTERN_BINDING_PROJECTION_CONTRACT,
        architecture=Architecture.RISC_V,
        artifact_id=graph.artifact_id,
        artifact_sha256=graph.artifact_sha256,
        source_static_analysis_result_id=(
            graph.source_static_analysis_result_id
        ),
        source_case_assembly_result_id="adapter-materialization:generic",
        source_pattern_id="generic-pattern",
        extraction_plan_id="generic-plan",
        records=[],
        diagnostic_codes=[
            "case_order_candidate_binding_count:0",
            "predicate_candidate_binding_count:0",
        ],
    )
    projection = StaticBehaviorAnalysisProjection.create(
        architecture=Architecture.RISC_V,
        artifact_id=graph.artifact_id,
        artifact_sha256=graph.artifact_sha256,
        source_analysis_result_id=graph.source_static_analysis_result_id,
        source_analysis_contract="generic-static-analysis-v1",
        program_graph=graph,
        pattern_bindings=bindings,
    )
    assert projection.architecture is Architecture.RISC_V
    assert projection.program_graph == graph
    assert projection.pattern_bindings == bindings
    assert "source_case_assembly_result_snapshot" not in (
        StaticBehaviorAnalysisProjection.model_fields
    )


def test_program_graph_and_pattern_bindings_are_separate(projection) -> None:
    graph = projection.program_graph
    bindings = projection.pattern_bindings
    assert Counter(item.kind for item in graph.nodes) == {
        StaticBehaviorNodeKind.FUNCTION: 1,
        StaticBehaviorNodeKind.BASIC_BLOCK: 2,
        StaticBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT: 2,
    }
    assert Counter(item.relation_kind for item in graph.relations) == {
        StaticBehaviorRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK: 2,
        StaticBehaviorRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT: 2,
        StaticBehaviorRelationKind.CFG_SUCCESSOR: 1,
    }
    assert Counter(item.binding_kind for item in bindings.records) == {
        StaticPatternBindingKind.PREDICATE_CANDIDATE: 2,
        StaticPatternBindingKind.CASE_ORDER_CANDIDATE: 1,
    }
    assert all(not item.causal for item in graph.relations)
    assert all(not item.runtime_execution for item in graph.relations)
    assert all(not item.symbolic_feasibility for item in graph.relations)


def test_semantic_fact_projection_is_explicit_but_outcome_neutral(projection) -> None:
    facts = [
        item
        for item in projection.program_graph.nodes
        if item.kind is StaticBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT
    ]
    assert {item.semantic_operation for item in facts} == {
        "store_exclusive",
        "memory_load",
    }
    for fact in facts:
        assert fact.instruction_address is not None
        assert fact.instruction_word is not None
        assert fact.instruction_size == 4
        assert fact.function_address is not None
        assert fact.function_name == "owned_static_projection_function"
        assert fact.basic_block_address is not None
        assert fact.semantic_attributes is not None
        assert fact.semantic_attributes.memory_type_resolution
        assert fact.semantic_attributes.static_fact_scope


def test_exact_candidate_references_and_obligations_are_preserved(
    projection, materialization,
) -> None:
    source = materialization.source_case_assembly_result_snapshot
    source_predicates = {
        item.id: item
        for item in source.source_extraction_result_snapshot.predicate_candidates
    }
    source_cases = {item.id: item for item in source.case_order_candidates}
    for record in projection.pattern_bindings.records:
        if record.binding_kind is StaticPatternBindingKind.PREDICATE_CANDIDATE:
            candidate = source_predicates[record.source_candidate_id]
            assert record.source_fact_id == candidate.static_instruction_fact_id
            assert record.remaining_objective_obligations == sorted(
                item.value
                for item in candidate.remaining_objective_obligations
            )
            assert record.binding_semantics is (
                StaticPatternBindingSemantics.CANDIDATE_FOR_PATTERN_PREDICATE
            )
        else:
            candidate = source_cases[record.source_case_order_candidate_id]
            assert record.remaining_objective_obligations == sorted(
                item.value
                for item in candidate.remaining_objective_obligations
            )
            assert record.witness_basic_block_path == (
                candidate.order_witness.witness_basic_block_path
            )


def test_a_profile_materialization_binds_exact_source_and_projection(
    plan, materialization,
) -> None:
    source = materialization.source_case_assembly_result_snapshot
    assert materialization.source_case_assembly_result_id == source.id
    assert materialization.projection.architecture is source.architecture
    assert materialization.projection.artifact_id == source.artifact_id
    assert materialization.projection.artifact_sha256 == source.artifact_sha256
    assert materialization.projection.source_analysis_result_id == (
        source.source_extraction_result_id
    )
    repeated = project_static_behavior_analysis(_synthetic_source(plan))
    assert repeated.projection == materialization.projection


def test_foreign_valid_a_profile_source_with_old_projection_fails(
    plan, materialization,
) -> None:
    foreign_source = _synthetic_source(
        plan, include_unprojected_fact=True
    )
    assert foreign_source.id != materialization.source_case_assembly_result_id
    payload = materialization.model_dump(mode="json")
    payload["source_case_assembly_result_id"] = foreign_source.id
    payload["source_case_assembly_result_snapshot"] = (
        foreign_source.model_dump(mode="json")
    )
    _recompute_materialization(payload)
    with pytest.raises(ValidationError, match="projection binding mismatch"):
        AProfileStaticBehaviorProjectionMaterialization.model_validate(payload)


def test_projection_is_deterministic_detached_and_ordered(plan) -> None:
    source = _synthetic_source(plan)
    first = project_static_behavior_analysis(source)
    second = project_static_behavior_analysis(source)
    assert first == second
    assert first.id == second.id
    assert first.model_dump_json() == second.model_dump_json()
    assert first.projection.program_graph.nodes == sorted(
        first.projection.program_graph.nodes,
        key=lambda item: (
            item.kind.value,
            int(item.function_address or "0x0", 16),
            int(item.basic_block_address or "0x0", 16),
            int(item.instruction_address or "0x0", 16),
            item.id,
        ),
    )
    source.function_cfg_snapshots.clear()
    assert first.source_case_assembly_result_snapshot.function_cfg_snapshots


def test_nonpredicate_fact_outside_relevant_cfg_is_neutrally_counted(plan) -> None:
    materialization = project_static_behavior_analysis(
        _synthetic_source(plan, include_unprojected_fact=True)
    )
    projection = materialization.projection
    assert projection.program_graph.unprojected_nonpredicate_fact_count == 1
    assert "unprojected_nonpredicate_fact_count:1" in (
        projection.program_graph.diagnostic_codes
    )
    assert sum(
        item.kind is StaticBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT
        for item in projection.program_graph.nodes
    ) == 2


def test_frozen_owned_fixture_projection_counts(plan) -> None:
    pytest.importorskip("angr")
    artifact = ProgramArtifact(
        id="owned-synthetic-a64-static-semantic-fixture",
        architecture=Architecture.ARM,
        artifact_type="elf",
        path=str(FIXTURE),
        fixture_identifier="phase10d-a-profile-static-semantic-a64",
        metadata={"owned": True, "synthetic": True, "fixture": True},
    )
    source = AngrAProfileStaticCaseMaterializer().materialize(artifact, plan)
    materialization = project_static_behavior_analysis(source)
    projection = materialization.projection
    assert source.id == (
        "a-profile-static-case-assembly-result:"
        "1c978aba6bbd83dfcd7d6cab1b1edf66eafc2f7c439156129e631a6785edf502"
    )
    assert Counter(item.kind for item in projection.program_graph.nodes) == {
        StaticBehaviorNodeKind.FUNCTION: 3,
        StaticBehaviorNodeKind.BASIC_BLOCK: 3,
        StaticBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT: 3,
    }
    assert Counter(
        item.relation_kind for item in projection.program_graph.relations
    ) == {
        StaticBehaviorRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK: 3,
        StaticBehaviorRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT: 3,
    }
    assert Counter(
        item.binding_kind for item in projection.pattern_bindings.records
    ) == {StaticPatternBindingKind.PREDICATE_CANDIDATE: 6}


def test_top_level_source_id_retarget_with_recomputed_id_fails(
    materialization,
) -> None:
    payload = materialization.model_dump(mode="json")
    payload["source_case_assembly_result_id"] = "retargeted-result"
    _recompute_materialization(payload)
    with pytest.raises(ValidationError, match="source snapshot ID mismatch"):
        AProfileStaticBehaviorProjectionMaterialization.model_validate(payload)


def test_graph_node_artifact_tamper_with_recomputed_ids_fails(projection) -> None:
    payload = projection.model_dump(mode="json")
    node = payload["program_graph"]["nodes"][0]
    old_id = node["id"]
    node["artifact_sha256"] = "b" * 64
    _recompute(node, "id", static_behavior_node_id)
    _replace_graph_node_id(payload, old_id=old_id, new_id=node["id"])
    _recompute_graph(payload)
    with pytest.raises(ValidationError, match="node artifact binding mismatch"):
        StaticBehaviorAnalysisProjection.model_validate(payload)


def test_semantic_node_source_fact_retarget_fails_exact_membership(projection) -> None:
    payload = projection.model_dump(mode="json")
    node = next(
        item
        for item in payload["program_graph"]["nodes"]
        if item["kind"] == "semantic_instruction_fact"
    )
    old_id = node["id"]
    node["source_object_id"] = "foreign-static-fact"
    _recompute(node, "id", static_behavior_node_id)
    _replace_graph_node_id(payload, old_id=old_id, new_id=node["id"])
    _recompute_graph(payload)
    with pytest.raises(ValidationError, match="source provenance is not exact"):
        StaticBehaviorAnalysisProjection.model_validate(payload)


def test_block_node_unknown_cfg_block_fails(projection) -> None:
    payload = projection.model_dump(mode="json")
    node = next(
        item
        for item in payload["program_graph"]["nodes"]
        if item["kind"] == "basic_block"
    )
    old_id = node["id"]
    node["basic_block_address"] = "0x0000000000990000"
    node["source_object_id"] = "foreign-cfg-block"
    _recompute(node, "id", static_behavior_node_id)
    _replace_graph_node_id(payload, old_id=old_id, new_id=node["id"])
    _recompute_graph(payload)
    with pytest.raises(ValidationError):
        StaticBehaviorAnalysisProjection.model_validate(payload)


def test_relation_dangling_endpoint_cross_artifact_and_assertion_fail(
    projection,
) -> None:
    dangling = projection.model_dump(mode="json")
    relation = dangling["program_graph"]["relations"][0]
    relation["target_node_id"] = "unknown-static-node"
    _recompute(relation, "id", static_behavior_relation_id)
    _recompute_graph(dangling)
    with pytest.raises(ValidationError, match="dangling endpoint"):
        StaticBehaviorAnalysisProjection.model_validate(dangling)

    cross_artifact = projection.model_dump(mode="json")
    relation = cross_artifact["program_graph"]["relations"][0]
    relation["artifact_sha256"] = "b" * 64
    _recompute(relation, "id", static_behavior_relation_id)
    _recompute_graph(cross_artifact)
    with pytest.raises(ValidationError, match="relation artifact binding"):
        StaticBehaviorAnalysisProjection.model_validate(cross_artifact)

    assertion = projection.model_dump(mode="json")
    assertion["program_graph"]["relations"][0]["assertion_class"] = (
        "objective_static_fact"
    )
    with pytest.raises(ValidationError):
        StaticBehaviorAnalysisProjection.model_validate(assertion)


def test_predicate_binding_wrong_fact_node_fails(projection) -> None:
    payload = projection.model_dump(mode="json")
    records = payload["pattern_bindings"]["records"]
    predicates = [
        item for item in records if item["binding_kind"] == "predicate_candidate"
    ]
    predicates[0]["semantic_fact_node_id"] = predicates[1][
        "semantic_fact_node_id"
    ]
    _recompute(predicates[0], "id", static_pattern_binding_record_id)
    _recompute_pattern(payload)
    with pytest.raises(ValidationError, match="exact fact node"):
        StaticBehaviorAnalysisProjection.model_validate(payload)


def test_case_order_binding_wrong_position_fact_node_fails(
    materialization,
) -> None:
    payload = materialization.model_dump(mode="json")
    projection_payload = payload["projection"]
    record = next(
        item
        for item in projection_payload["pattern_bindings"]["records"]
        if item["binding_kind"] == "case_order_candidate"
    )
    record["position_1_fact_node_id"] = record["position_2_fact_node_id"]
    _recompute(record, "id", static_pattern_binding_record_id)
    _recompute_pattern(projection_payload)
    _recompute_materialization(payload)
    with pytest.raises(ValidationError, match="differs from exact source"):
        AProfileStaticBehaviorProjectionMaterialization.model_validate(payload)


def test_mutated_generic_projection_with_exact_source_fails(
    materialization,
) -> None:
    payload = materialization.model_dump(mode="json")
    projection_payload = payload["projection"]
    record = next(
        item
        for item in projection_payload["pattern_bindings"]["records"]
        if item["binding_kind"] == "predicate_candidate"
    )
    record["source_candidate_id"] = "foreign-pattern-candidate"
    _recompute(record, "id", static_pattern_binding_record_id)
    _recompute_pattern(projection_payload)
    _recompute_materialization(payload)
    with pytest.raises(ValidationError, match="differs from exact source"):
        AProfileStaticBehaviorProjectionMaterialization.model_validate(payload)


def test_dropped_obligation_and_foreign_candidate_fail(
    materialization,
) -> None:
    dropped = materialization.model_dump(mode="json")
    dropped_projection = dropped["projection"]
    record = next(
        item
        for item in dropped_projection["pattern_bindings"]["records"]
        if item["binding_kind"] == "predicate_candidate"
    )
    record["remaining_objective_obligations"].remove(
        RemainingObjectiveObligation.RUNTIME_EXECUTION_REQUIRED.value
    )
    _recompute(record, "id", static_pattern_binding_record_id)
    _recompute_pattern(dropped_projection)
    _recompute_materialization(dropped)
    with pytest.raises(ValidationError, match="differs from exact source"):
        AProfileStaticBehaviorProjectionMaterialization.model_validate(dropped)

    foreign = materialization.model_dump(mode="json")
    foreign_projection = foreign["projection"]
    record = next(
        item
        for item in foreign_projection["pattern_bindings"]["records"]
        if item["binding_kind"] == "predicate_candidate"
    )
    record["source_candidate_id"] = "foreign-pattern-candidate"
    _recompute(record, "id", static_pattern_binding_record_id)
    _recompute_pattern(foreign_projection)
    _recompute_materialization(foreign)
    with pytest.raises(ValidationError, match="differs from exact source"):
        AProfileStaticBehaviorProjectionMaterialization.model_validate(foreign)


def test_objective_causal_and_verification_firewalls() -> None:
    forbidden = {
        "triggers",
        "exploits",
        "causes",
        "verified",
        "triggerable",
        "feasible_attack",
        "runtime_executed",
        "proximity_satisfied",
    }
    enum_values = {
        item.value
        for enum_type in (
            StaticAssertionClass,
            StaticBehaviorNodeKind,
            StaticBehaviorRelationKind,
            StaticBehaviorProjectionScope,
            StaticPatternBindingKind,
            StaticPatternBindingSemantics,
            StaticPatternOrderBasis,
            StaticPatternPathWitnessUse,
            StaticObjectiveObligation,
        )
        for item in enum_type
    }
    assert forbidden.isdisjoint(enum_values)
    relation_schema = StaticBehaviorAnalysisProjection.model_json_schema()
    serialized_schema = str(relation_schema).lower()
    assert "attack_chain" not in serialized_schema
    assert "cross_layer_interaction" not in serialized_schema
    assert "verificationrecord" not in serialized_schema


def test_public_models_reject_verdict_attributes_and_true_edge_claims(
    projection,
) -> None:
    attribute_payload = projection.model_dump(mode="json")
    fact = next(
        item
        for item in attribute_payload["program_graph"]["nodes"]
        if item["kind"] == "semantic_instruction_fact"
    )
    fact["semantic_attributes"]["verification_status"] = "verified"
    with pytest.raises(ValidationError):
        StaticBehaviorAnalysisProjection.model_validate(attribute_payload)

    operation_payload = projection.model_dump(mode="json")
    fact = next(
        item
        for item in operation_payload["program_graph"]["nodes"]
        if item["kind"] == "semantic_instruction_fact"
    )
    fact["semantic_operation"] = "verified"
    with pytest.raises(ValidationError, match="outcome-neutral"):
        StaticBehaviorAnalysisProjection.model_validate(operation_payload)

    for field in ("causal", "runtime_execution", "symbolic_feasibility"):
        relation_payload = projection.model_dump(mode="json")
        relation_payload["program_graph"]["relations"][0][field] = True
        with pytest.raises(ValidationError):
            StaticBehaviorAnalysisProjection.model_validate(relation_payload)


def test_shared_production_models_have_no_fixture_specific_constants() -> None:
    paths = [
        ROOT / "src/chipchain/analysis/static_behavior_models.py",
        ROOT / "src/chipchain/analysis/static_behavior_projection.py",
    ]
    forbidden = (
        "CVE-2023-34320",
        "1508412",
        "Cortex-A77",
        "case_a",
        "case_b",
        "PAR_EL1",
        "STXR",
        "LDR",
    )
    for path in paths:
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        string_constants = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        assert not any(value in string_constants for value in forbidden)
        imported_names = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        assert {
            "Evidence",
            "VerificationRecord",
            "TriggerabilityAggregationResult",
            "ChainFeasibilityAssessment",
            "AttackChain",
            "CrossLayerInteraction",
            "ReasoningContext",
        }.isdisjoint(imported_names)
