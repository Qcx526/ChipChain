"""Contracts for provenance-bound static semantic/structure fusion."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from pathlib import Path
import runpy

from pydantic import ValidationError
import pytest

from chipchain.analysis import (
    AngrAArch64StaticProgramStructureExtractor,
    AngrAArch64StaticSemanticDecoder,
    PHASE10D_STATIC_FUSED_BEHAVIOR_GRAPH_MATERIALIZATION_CONTRACT,
    PHASE10D_STATIC_FUSED_BEHAVIOR_GRAPH_PROJECTION_CONTRACT,
    PHASE10D_STATIC_FUSED_BEHAVIOR_NODE_CONTRACT,
    PHASE10D_STATIC_FUSED_BEHAVIOR_RELATION_CONTRACT,
    ProgramArtifact,
    StaticFusedBehaviorGraphMaterialization,
    StaticFusedBehaviorGraphProjection,
    StaticFusedBehaviorNode,
    StaticFusedBehaviorNodeKind,
    StaticFusedBehaviorProjectionScope,
    StaticFusedBehaviorRelation,
    StaticFusedBehaviorRelationKind,
    StaticProgramCfgSemantics,
    StaticProgramFunctionCfg,
    StaticProgramStructureInventory,
    StaticSemanticFactScope,
    StaticSemanticInstructionFact,
    StaticSemanticInventory,
    StaticSemanticInventoryScope,
    StaticSemanticOperation,
    fuse_static_semantic_and_program_structure,
    project_static_semantic_inventory,
    static_fused_behavior_graph_materialization_id,
    static_fused_behavior_graph_projection_id,
    static_fused_behavior_node_id,
    static_fused_behavior_relation_id,
    static_program_basic_block_source_id,
)
from chipchain.models import Architecture


ROOT = Path(__file__).resolve().parents[1]
FUSION_FIXTURE_DIRECTORY = (
    ROOT / "tests/fixtures/phase10d/aarch64_static_fused_behavior_v1"
)
FUSION_FIXTURE = (
    FUSION_FIXTURE_DIRECTORY / "aarch64_static_fused_behavior_v1.elf"
)
FUSION_DESIGN = (
    FUSION_FIXTURE_DIRECTORY / "expected_fixture_design.json"
)
GENERIC_FIXTURE = (
    ROOT
    / "tests/fixtures/phase10d/aarch64_generic_static_semantic_v1/"
    "aarch64_generic_static_semantic_v1.elf"
)
STRUCTURE_FIXTURE = (
    ROOT
    / "tests/fixtures/phase10d/aarch64_static_program_structure_v1/"
    "aarch64_static_program_structure_v1.elf"
)
FUSION_FIXTURE_SHA256 = (
    "3d92da1b6f160605df23514a43c04631e0c64f275cd707720988765f727e3262"
)
FUSION_ARTIFACT_ID = "owned-synthetic-aarch64-static-fused-behavior-v1"
CFG_SEMANTICS = (
    StaticProgramCfgSemantics
    .FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1
)


def _artifact(
    path: Path,
    artifact_id: str,
    fixture_id: str,
) -> ProgramArtifact:
    return ProgramArtifact(
        id=artifact_id,
        architecture=Architecture.ARM,
        artifact_type="elf",
        path=str(path),
        fixture_identifier=fixture_id,
        metadata={"owned": True, "synthetic": True, "fixture": True},
    )


def _analyzed_sources(
    path: Path,
    artifact_id: str,
    fixture_id: str,
):
    pytest.importorskip("angr")
    artifact = _artifact(path, artifact_id, fixture_id)
    semantic = AngrAArch64StaticSemanticDecoder().decode(artifact)
    graph = project_static_semantic_inventory(semantic)
    structure = AngrAArch64StaticProgramStructureExtractor().extract(artifact)
    return semantic, graph, structure


@pytest.fixture(scope="module")
def fusion_sources():
    return _analyzed_sources(
        FUSION_FIXTURE,
        FUSION_ARTIFACT_ID,
        "phase10d-aarch64-static-fused-behavior-v1",
    )


@pytest.fixture(scope="module")
def fused(fusion_sources):
    _semantic, graph, structure = fusion_sources
    return fuse_static_semantic_and_program_structure(graph, structure)


@pytest.fixture(scope="module")
def generic_fused():
    _semantic, graph, structure = _analyzed_sources(
        GENERIC_FIXTURE,
        "owned-synthetic-generic-aarch64-v1",
        "phase10d-aarch64-generic-static-semantic-v1",
    )
    return fuse_static_semantic_and_program_structure(graph, structure)


@pytest.fixture(scope="module")
def structure_fused():
    _semantic, graph, structure = _analyzed_sources(
        STRUCTURE_FIXTURE,
        "owned-synthetic-aarch64-static-program-structure-v1",
        "phase10d-aarch64-static-program-structure-v1",
    )
    return fuse_static_semantic_and_program_structure(graph, structure)


def _synthetic_sources(
    *,
    semantic_function_name: str | None = "semantic_name",
    semantic_function_address: str | None = "0x500000",
    semantic_block_address: str | None = "0x500010",
    structure_function_name: str | None = "semantic_name",
    structure_architecture: Architecture = Architecture.ARM,
    structure_artifact_id: str = "owned-synthetic-fusion-contract",
    structure_artifact_sha256: str = "a" * 64,
    structure_instruction_set: str = "aarch64",
):
    artifact_id = "owned-synthetic-fusion-contract"
    artifact_sha256 = "a" * 64
    fact = StaticSemanticInstructionFact.create(
        architecture=Architecture.ARM,
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        decoder_profile_id="owned-synthetic-semantic-decoder-v1",
        instruction_set="aarch64",
        instruction_address="0x500010",
        instruction_bytes="0x200040f9",
        instruction_size=4,
        function_address=semantic_function_address,
        function_name=semantic_function_name,
        basic_block_address=semantic_block_address,
        operation=StaticSemanticOperation.MEMORY_LOAD,
        fact_scope=(
            StaticSemanticFactScope
            .DECODED_STATIC_INSTRUCTION_SEMANTICS_ONLY
        ),
    )
    inventory = StaticSemanticInventory.create(
        architecture=Architecture.ARM,
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        decoder_profile_id=fact.decoder_profile_id,
        instruction_set="aarch64",
        analysis_scope=(
            StaticSemanticInventoryScope
            .PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY
        ),
        facts=[fact],
        diagnostic_codes=["semantic_fact_count:1"],
    )
    graph = project_static_semantic_inventory(inventory)
    function = StaticProgramFunctionCfg.create(
        architecture=structure_architecture,
        artifact_id=structure_artifact_id,
        artifact_sha256=structure_artifact_sha256,
        analyzer_profile_id="owned-synthetic-structure-extractor-v1",
        instruction_set=structure_instruction_set,
        function_address="0x500000",
        function_name=structure_function_name,
        basic_block_addresses=["0x500010"],
        directed_edges=[],
        cfg_semantics=CFG_SEMANTICS,
    )
    structure = StaticProgramStructureInventory.create(
        architecture=structure_architecture,
        artifact_id=structure_artifact_id,
        artifact_sha256=structure_artifact_sha256,
        analyzer_profile_id=function.analyzer_profile_id,
        instruction_set=structure_instruction_set,
        functions=[function],
    )
    return graph, structure


def _nodes(materialization, kind):
    return [
        node
        for node in materialization.projection.nodes
        if node.kind is kind
    ]


def _relations(materialization, kind):
    return [
        relation
        for relation in materialization.projection.relations
        if relation.relation_kind is kind
    ]


def test_public_api_has_exactly_two_logical_inputs() -> None:
    signature = inspect.signature(fuse_static_semantic_and_program_structure)

    assert list(signature.parameters) == [
        "semantic_graph_materialization",
        "structure_inventory",
    ]
    assert signature.return_annotation == (
        "StaticFusedBehaviorGraphMaterialization"
    )


def test_contract_family_and_vocabularies_are_exact() -> None:
    assert PHASE10D_STATIC_FUSED_BEHAVIOR_NODE_CONTRACT == (
        "phase10d_static_fused_behavior_node_v1"
    )
    assert PHASE10D_STATIC_FUSED_BEHAVIOR_RELATION_CONTRACT == (
        "phase10d_static_fused_behavior_relation_v1"
    )
    assert PHASE10D_STATIC_FUSED_BEHAVIOR_GRAPH_PROJECTION_CONTRACT == (
        "phase10d_static_fused_behavior_graph_projection_v1"
    )
    assert PHASE10D_STATIC_FUSED_BEHAVIOR_GRAPH_MATERIALIZATION_CONTRACT == (
        "phase10d_static_fused_behavior_graph_materialization_v1"
    )
    assert list(StaticFusedBehaviorNodeKind) == [
        StaticFusedBehaviorNodeKind.FUNCTION,
        StaticFusedBehaviorNodeKind.BASIC_BLOCK,
        StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT,
    ]
    assert list(StaticFusedBehaviorRelationKind) == [
        StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK,
        StaticFusedBehaviorRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT,
        StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT,
        StaticFusedBehaviorRelationKind.CFG_SUCCESSOR,
    ]
    assert list(StaticFusedBehaviorProjectionScope) == [
        StaticFusedBehaviorProjectionScope
        .PARTIAL_PROVENANCE_BOUND_SEMANTIC_STRUCTURE_STATIC_BEHAVIOR_GRAPH
    ]


def test_v1_schema_locks_exact_contract_and_vocabularies() -> None:
    node_schema = StaticFusedBehaviorNode.model_json_schema()
    relation_schema = StaticFusedBehaviorRelation.model_json_schema()
    projection_schema = StaticFusedBehaviorGraphProjection.model_json_schema()
    materialization_schema = (
        StaticFusedBehaviorGraphMaterialization.model_json_schema()
    )

    assert node_schema["properties"]["contract"]["const"] == (
        "phase10d_static_fused_behavior_node_v1"
    )
    assert node_schema["properties"]["kind"]["enum"] == [
        "function",
        "basic_block",
        "semantic_instruction_fact",
    ]
    assert relation_schema["properties"]["contract"]["const"] == (
        "phase10d_static_fused_behavior_relation_v1"
    )
    assert relation_schema["properties"]["relation_kind"]["enum"] == [
        "function_contains_basic_block",
        "basic_block_contains_semantic_fact",
        "function_contains_semantic_fact",
        "cfg_successor",
    ]
    assert projection_schema["properties"]["projection_scope"]["const"] == (
        "partial_provenance_bound_semantic_structure_static_behavior_graph"
    )
    assert materialization_schema["properties"]["contract"]["const"] == (
        "phase10d_static_fused_behavior_graph_materialization_v1"
    )


@pytest.mark.angr
def test_owned_fixture_is_deterministic_and_not_ground_truth() -> None:
    design = json.loads(FUSION_DESIGN.read_text(encoding="utf-8"))
    namespace = runpy.run_path(
        str(FUSION_FIXTURE_DIRECTORY / "generate_fixture.py")
    )
    generated, generated_design = namespace["build_elf"]()
    expected_without_hash = dict(design)
    expected_without_hash.pop("artifact_sha256")

    assert hashlib.sha256(FUSION_FIXTURE.read_bytes()).hexdigest() == (
        FUSION_FIXTURE_SHA256
    )
    assert generated == FUSION_FIXTURE.read_bytes()
    assert generated_design == expected_without_hash
    assert design["fixture_classification"] == {
        "owned": True,
        "synthetic": True,
        "benign": True,
        "real_vulnerability": False,
        "runtime_execution_evidence": False,
        "triggerability_demonstration": False,
        "verified_attack_chain": False,
    }
    assert not (FUSION_FIXTURE_DIRECTORY / "ground_truth.json").exists()


@pytest.mark.angr
def test_owned_sources_match_exact_fixture_design(fusion_sources) -> None:
    semantic, _graph, structure = fusion_sources
    design = json.loads(FUSION_DESIGN.read_text(encoding="utf-8"))
    expected_facts = [
        (
            instruction["address"],
            instruction["intended_recognized_semantic"],
        )
        for instruction in design["instructions"]
        if instruction["intended_recognized_semantic"] is not None
    ]
    function = structure.functions[0]

    assert semantic.artifact_sha256 == FUSION_FIXTURE_SHA256
    assert [
        (fact.instruction_address, fact.operation.value)
        for fact in semantic.facts
    ] == expected_facts
    assert len(structure.functions) == 1
    assert function.function_name == design["function_name"]
    assert function.basic_block_addresses == design[
        "intended_basic_block_addresses"
    ]
    assert [
        [edge.source_basic_block_address, edge.target_basic_block_address]
        for edge in function.directed_edges
    ] == design["intended_cfg_edges"]


@pytest.mark.angr
def test_owned_fused_graph_has_exact_nodes_and_relations(fused) -> None:
    assert len(_nodes(fused, StaticFusedBehaviorNodeKind.FUNCTION)) == 1
    assert len(_nodes(fused, StaticFusedBehaviorNodeKind.BASIC_BLOCK)) == 4
    assert len(
        _nodes(fused, StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT)
    ) == 4
    assert len(
        _relations(
            fused,
            StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK,
        )
    ) == 4
    assert len(
        _relations(
            fused,
            StaticFusedBehaviorRelationKind
            .BASIC_BLOCK_CONTAINS_SEMANTIC_FACT,
        )
    ) == 4
    assert len(
        _relations(fused, StaticFusedBehaviorRelationKind.CFG_SUCCESSOR)
    ) == 4


@pytest.mark.angr
def test_owned_nodes_preserve_dual_source_provenance(fused) -> None:
    functions = _nodes(fused, StaticFusedBehaviorNodeKind.FUNCTION)
    blocks = _nodes(fused, StaticFusedBehaviorNodeKind.BASIC_BLOCK)
    facts = _nodes(
        fused, StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT
    )

    assert all(node.semantic_source_node_ids for node in functions + blocks)
    assert all(node.structure_function_cfg_ids for node in functions + blocks)
    assert all(node.structure_basic_block_source_ids for node in blocks)
    assert all(len(node.semantic_source_node_ids) == 1 for node in facts)
    assert all(not node.structure_function_cfg_ids for node in facts)


@pytest.mark.angr
def test_cfg_successors_preserve_exact_structure_edges(
    fused, fusion_sources
) -> None:
    _semantic, _graph, structure = fusion_sources
    function = structure.functions[0]
    blocks = {
        node.id: node
        for node in _nodes(fused, StaticFusedBehaviorNodeKind.BASIC_BLOCK)
    }
    successors = _relations(
        fused, StaticFusedBehaviorRelationKind.CFG_SUCCESSOR
    )

    assert {
        (
            blocks[relation.source_node_id].basic_block_address,
            blocks[relation.target_node_id].basic_block_address,
        )
        for relation in successors
    } == {
        (
            edge.source_basic_block_address,
            edge.target_basic_block_address,
        )
        for edge in function.directed_edges
    }
    assert {relation.structure_cfg_edge_ids[0] for relation in successors} == {
        edge.id for edge in function.directed_edges
    }
    for relation in successors:
        assert relation.structure_function_cfg_ids == [function.id]
        assert relation.cfg_semantics is CFG_SEMANTICS
        assert not relation.causal
        assert not relation.runtime_execution
        assert not relation.symbolic_feasibility


@pytest.mark.angr
def test_generic_eret_remains_function_contained_only(generic_fused) -> None:
    functions = _nodes(generic_fused, StaticFusedBehaviorNodeKind.FUNCTION)
    blocks = _nodes(generic_fused, StaticFusedBehaviorNodeKind.BASIC_BLOCK)
    facts = _nodes(
        generic_fused,
        StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT,
    )
    eret = next(
        node
        for node in facts
        if node.operation is StaticSemanticOperation.EXCEPTION_RETURN
    )
    function = next(
        node for node in functions if node.function_address == "0x400034"
    )
    relation = next(
        item
        for item in _relations(
            generic_fused,
            StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT,
        )
        if item.source_node_id == function.id and item.target_node_id == eret.id
    )

    assert eret.instruction_address == "0x400034"
    assert eret.function_address == "0x400034"
    assert eret.basic_block_address is None
    assert relation.semantic_source_relation_ids
    assert not any(
        node.function_address == "0x400034"
        and node.basic_block_address == "0x400034"
        for node in blocks
    )
    assert not _relations(
        generic_fused, StaticFusedBehaviorRelationKind.CFG_SUCCESSOR
    )


@pytest.mark.angr
def test_structure_only_topology_is_not_reduced(structure_fused) -> None:
    blocks = {
        node.id: node
        for node in _nodes(
            structure_fused, StaticFusedBehaviorNodeKind.BASIC_BLOCK
        )
    }
    successors = _relations(
        structure_fused, StaticFusedBehaviorRelationKind.CFG_SUCCESSOR
    )

    assert len(blocks) == 5
    assert {
        (
            blocks[relation.source_node_id].basic_block_address,
            blocks[relation.target_node_id].basic_block_address,
        )
        for relation in successors
    } == {
        ("0x400000", "0x400004"),
        ("0x400000", "0x40000c"),
        ("0x400018", "0x400018"),
    }


def test_unscoped_semantic_block_does_not_merge_by_raw_address() -> None:
    graph, structure = _synthetic_sources(
        semantic_function_name=None,
        semantic_function_address=None,
        semantic_block_address="0x500010",
        structure_function_name="structure_name",
    )
    fused = fuse_static_semantic_and_program_structure(graph, structure)
    matching = [
        node
        for node in _nodes(fused, StaticFusedBehaviorNodeKind.BASIC_BLOCK)
        if node.basic_block_address == "0x500010"
    ]

    assert len(matching) == 2
    assert {node.function_address for node in matching} == {
        None,
        "0x500000",
    }
    assert sum(bool(node.semantic_source_node_ids) for node in matching) == 1
    assert sum(bool(node.structure_basic_block_source_ids) for node in matching) == 1


def test_none_block_provenance_never_uses_same_instruction_address() -> None:
    graph, structure = _synthetic_sources(semantic_block_address=None)
    fused = fuse_static_semantic_and_program_structure(graph, structure)
    fact = _nodes(
        fused, StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT
    )[0]
    blocks = _nodes(fused, StaticFusedBehaviorNodeKind.BASIC_BLOCK)

    assert fact.instruction_address == "0x500010"
    assert fact.basic_block_address is None
    assert len(blocks) == 1
    assert blocks[0].basic_block_address == "0x500010"
    assert not any(
        relation.target_node_id == fact.id
        for relation in _relations(
            fused,
            StaticFusedBehaviorRelationKind
            .BASIC_BLOCK_CONTAINS_SEMANTIC_FACT,
        )
    )
    assert any(
        relation.target_node_id == fact.id
        for relation in _relations(
            fused,
            StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT,
        )
    )


def test_function_name_conflict_fails_closed() -> None:
    graph, structure = _synthetic_sources(
        semantic_function_name="semantic_name",
        structure_function_name="structure_name",
    )

    with pytest.raises(ValueError, match="function names conflict"):
        fuse_static_semantic_and_program_structure(graph, structure)


def test_one_non_none_function_name_is_preserved() -> None:
    graph, structure = _synthetic_sources(
        semantic_function_name="semantic_name",
        structure_function_name=None,
    )

    fused = fuse_static_semantic_and_program_structure(graph, structure)

    assert _nodes(fused, StaticFusedBehaviorNodeKind.FUNCTION)[0].function_name == (
        "semantic_name"
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"structure_architecture": Architecture.RISC_V},
        {"structure_artifact_id": "owned-synthetic-other-artifact"},
        {"structure_artifact_sha256": "b" * 64},
        {"structure_instruction_set": "rv64gc"},
    ],
)
def test_source_provenance_mismatch_fails_before_reconciliation(
    overrides: dict[str, object],
) -> None:
    graph, structure = _synthetic_sources(
        structure_function_name="structure_name",
        **overrides,
    )

    with pytest.raises(ValueError, match="provenance does not match exactly"):
        fuse_static_semantic_and_program_structure(graph, structure)


def test_semantic_and_structure_membership_merge_without_duplication() -> None:
    graph, structure = _synthetic_sources()
    fused = fuse_static_semantic_and_program_structure(graph, structure)
    memberships = _relations(
        fused,
        StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK,
    )

    assert len(memberships) == 1
    assert len(memberships[0].semantic_source_relation_ids) == 1
    assert len(memberships[0].structure_function_cfg_ids) == 1
    assert len(memberships[0].structure_basic_block_source_ids) == 1


def test_structure_never_creates_semantic_fact_containment() -> None:
    graph, structure = _synthetic_sources()
    fused = fuse_static_semantic_and_program_structure(graph, structure)
    containment = _relations(
        fused,
        StaticFusedBehaviorRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT,
    )[0]

    assert len(containment.semantic_source_relation_ids) == 1
    assert not containment.structure_function_cfg_ids
    assert not containment.structure_basic_block_source_ids
    assert not containment.structure_cfg_edge_ids


def test_structure_block_provenance_uses_frozen_helper() -> None:
    graph, structure = _synthetic_sources()
    fused = fuse_static_semantic_and_program_structure(graph, structure)
    function = structure.functions[0]
    block = _nodes(fused, StaticFusedBehaviorNodeKind.BASIC_BLOCK)[0]

    assert block.structure_basic_block_source_ids == [
        static_program_basic_block_source_id(function.id, "0x500010")
    ]


def test_fusion_is_deterministic_and_input_order_independent() -> None:
    graph, structure = _synthetic_sources()
    first = fuse_static_semantic_and_program_structure(graph, structure)
    graph_payload = graph.model_dump(mode="json")
    structure_payload = structure.model_dump(mode="json")
    graph_payload["projection"]["nodes"].reverse()
    graph_payload["projection"]["relations"].reverse()
    structure_payload["functions"].reverse()
    reordered_graph = type(graph).model_validate(graph_payload)
    reordered_structure = type(structure).model_validate(structure_payload)
    second = fuse_static_semantic_and_program_structure(
        reordered_graph, reordered_structure
    )

    assert first == second
    assert first.id == second.id
    assert first.projection.id == second.projection.id


def test_caller_mutation_after_fusion_does_not_change_result() -> None:
    graph, structure = _synthetic_sources()
    fused = fuse_static_semantic_and_program_structure(graph, structure)
    before = fused.model_dump_json()

    graph.projection.nodes.clear()
    structure.functions.clear()

    assert fused.model_dump_json() == before


def _tampered_payload() -> dict:
    graph, structure = _synthetic_sources()
    return fuse_static_semantic_and_program_structure(
        graph, structure
    ).model_dump(mode="json")


def _validate_tamper(payload: dict) -> None:
    with pytest.raises((ValidationError, ValueError)):
        StaticFusedBehaviorGraphMaterialization.model_validate(payload)


def _recompute_id(payload: dict, id_function) -> None:
    payload["id"] = id_function(
        {key: value for key, value in payload.items() if key != "id"}
    )


def _recompute_projection_and_materialization_ids(payload: dict) -> None:
    _recompute_id(
        payload["projection"], static_fused_behavior_graph_projection_id
    )
    _recompute_id(payload, static_fused_behavior_graph_materialization_id)


def test_semantic_source_snapshot_tampering_fails_closed() -> None:
    payload = _tampered_payload()
    payload["source_semantic_graph_materialization"][
        "source_inventory_snapshot"
    ]["artifact_id"] = "owned-synthetic-tampered-semantic-source"

    _validate_tamper(payload)


def test_rehashed_foreign_semantic_provenance_is_rejected_by_source_reprojection(
) -> None:
    payload = _tampered_payload()
    projection = payload["projection"]
    source_projection = payload["source_semantic_graph_materialization"][
        "projection"
    ]
    fact = next(
        node
        for node in projection["nodes"]
        if node["kind"] == "semantic_instruction_fact"
    )
    original_node_id = fact["id"]
    foreign_source_id = f"static-semantic-graph-node:{'f' * 64}"
    assert foreign_source_id not in {
        node["id"] for node in source_projection["nodes"]
    }

    fact["semantic_source_node_ids"] = [foreign_source_id]
    _recompute_id(fact, static_fused_behavior_node_id)
    for relation in projection["relations"]:
        endpoint_changed = False
        if relation["source_node_id"] == original_node_id:
            relation["source_node_id"] = fact["id"]
            endpoint_changed = True
        if relation["target_node_id"] == original_node_id:
            relation["target_node_id"] = fact["id"]
            endpoint_changed = True
        if endpoint_changed:
            _recompute_id(relation, static_fused_behavior_relation_id)
    _recompute_projection_and_materialization_ids(payload)

    # Projection proves internal deterministic graph integrity. The
    # materialization is authoritative for detached-source referential
    # integrity because it reprojects both source snapshots.
    StaticFusedBehaviorGraphProjection.model_validate(projection)
    with pytest.raises(ValidationError, match="deterministic reprojection"):
        StaticFusedBehaviorGraphMaterialization.model_validate(payload)


@pytest.mark.angr
def test_rehashed_foreign_structure_cfg_provenance_is_rejected_by_source_reprojection(
    structure_fused,
) -> None:
    payload = structure_fused.model_dump(mode="json")
    projection = payload["projection"]
    source_structure = payload["source_structure_inventory_snapshot"]
    cfg_relation = next(
        relation
        for relation in projection["relations"]
        if relation["relation_kind"] == "cfg_successor"
    )
    foreign_edge_id = f"static-program-cfg-edge:{'f' * 64}"
    assert foreign_edge_id not in {
        edge["id"]
        for function in source_structure["functions"]
        for edge in function["directed_edges"]
    }

    cfg_relation["structure_cfg_edge_ids"] = [foreign_edge_id]
    _recompute_id(cfg_relation, static_fused_behavior_relation_id)
    _recompute_projection_and_materialization_ids(payload)

    # A standalone projection cannot inspect external structure snapshots;
    # authoritative materialization validation must reject the foreign edge.
    StaticFusedBehaviorGraphProjection.model_validate(projection)
    with pytest.raises(ValidationError, match="deterministic reprojection"):
        StaticFusedBehaviorGraphMaterialization.model_validate(payload)


@pytest.mark.parametrize(
    "target",
    [
        "semantic_source_node_id",
        "semantic_source_relation_id",
        "structure_function_cfg_id",
        "structure_block_source_id",
        "fused_node_id",
        "fused_relation_id",
        "projection_id",
        "materialization_id",
        "source_snapshot",
        "diagnostics",
    ],
)
def test_identity_and_snapshot_tampering_fails_closed(target: str) -> None:
    payload = _tampered_payload()
    if target == "semantic_source_node_id":
        payload["projection"]["nodes"][0]["semantic_source_node_ids"][0] = (
            "static-semantic-graph-node:tampered"
        )
    elif target == "semantic_source_relation_id":
        payload["projection"]["relations"][0][
            "semantic_source_relation_ids"
        ][0] = "static-semantic-graph-relation:tampered"
    elif target == "structure_function_cfg_id":
        payload["projection"]["nodes"][0]["structure_function_cfg_ids"][0] = (
            "static-program-function-cfg:tampered"
        )
    elif target == "structure_block_source_id":
        block = next(
            node
            for node in payload["projection"]["nodes"]
            if node["kind"] == "basic_block"
        )
        block["structure_basic_block_source_ids"][0] = (
            "static-program-basic-block-source:tampered"
        )
    elif target == "fused_node_id":
        payload["projection"]["nodes"][0]["id"] = (
            "static-fused-behavior-node:tampered"
        )
    elif target == "fused_relation_id":
        payload["projection"]["relations"][0]["id"] = (
            "static-fused-behavior-relation:tampered"
        )
    elif target == "projection_id":
        payload["projection"]["id"] = (
            "static-fused-behavior-graph-projection:tampered"
        )
    elif target == "materialization_id":
        payload["id"] = "static-fused-behavior-graph-materialization:tampered"
    elif target == "source_snapshot":
        payload["source_structure_inventory_snapshot"]["artifact_id"] = (
            "owned-synthetic-tampered"
        )
    else:
        payload["projection"]["diagnostic_codes"][0] = "tampered:1"
    _validate_tamper(payload)


@pytest.mark.angr
def test_structure_cfg_edge_source_tampering_fails_closed() -> None:
    _semantic, graph, structure = _analyzed_sources(
        STRUCTURE_FIXTURE,
        "owned-synthetic-aarch64-static-program-structure-v1",
        "phase10d-aarch64-static-program-structure-v1",
    )
    payload = fuse_static_semantic_and_program_structure(
        graph, structure
    ).model_dump(mode="json")
    cfg = next(
        relation
        for relation in payload["projection"]["relations"]
        if relation["relation_kind"] == "cfg_successor"
    )
    cfg["structure_cfg_edge_ids"][0] = "static-program-cfg-edge:tampered"

    _validate_tamper(payload)


@pytest.mark.parametrize(
    "flag",
    ["causal", "runtime_execution", "symbolic_feasibility"],
)
def test_non_static_relation_flag_tampering_fails_closed(flag: str) -> None:
    payload = _tampered_payload()
    payload["projection"]["relations"][0][flag] = True

    _validate_tamper(payload)


def test_core_dependency_firewall() -> None:
    paths = [
        ROOT / "src/chipchain/analysis/static_fused_behavior_models.py",
        ROOT / "src/chipchain/analysis/static_fused_behavior_fusion.py",
    ]
    imported: set[str] = set()
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported.update(
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        imported.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
    forbidden = (
        "angr",
        "capstone",
        "chipchain.analysis.aarch64_static_semantic_decoder",
        "chipchain.analysis.aarch64_static_program_structure_extractor",
        "chipchain.hardware_trigger",
        "chipchain.knowledge",
        "chipchain.reasoning",
        "chipchain.runtime",
        "chipchain.verification",
        "chipchain.multi_agent",
    )

    assert not any(
        name == item or name.startswith(f"{item}.")
        for name in imported
        for item in forbidden
    )


def test_contract_schema_has_no_outcome_or_external_input_fields() -> None:
    schema = str(
        StaticFusedBehaviorGraphMaterialization.model_json_schema()
    ).lower()

    for forbidden in (
        "programartifact",
        "binary_path",
        "cve",
        "pattern",
        "predicate",
        "candidate",
        "knowledge",
        "reasoning",
        "verificationrecord",
        "runtimeevidence",
        "attackchain",
        "coverage_score",
        "confidence",
    ):
        assert forbidden not in schema
