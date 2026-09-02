"""Contracts for plan-independent static semantic inventory projection."""

from __future__ import annotations

import ast
from collections import Counter
import inspect
from pathlib import Path

from pydantic import ValidationError
import pytest

from chipchain.analysis import (
    PHASE10D_STATIC_SEMANTIC_GRAPH_MATERIALIZATION_CONTRACT,
    PHASE10D_STATIC_SEMANTIC_GRAPH_PROJECTION_CONTRACT,
    PHASE10D_STATIC_SEMANTIC_INVENTORY_CONTRACT,
    AngrAArch64StaticSemanticDecoder,
    ProgramArtifact,
    StaticSemanticAttribute,
    StaticSemanticAttributeName,
    StaticSemanticFactScope,
    StaticSemanticGraphNode,
    StaticSemanticGraphNodeKind,
    StaticSemanticGraphProjection,
    StaticSemanticGraphProjectionMaterialization,
    StaticSemanticGraphProjectionScope,
    StaticSemanticGraphRelation,
    StaticSemanticGraphRelationKind,
    StaticSemanticInstructionFact,
    StaticSemanticInventory,
    StaticSemanticInventoryScope,
    StaticSemanticOperation,
    project_static_semantic_inventory,
    static_semantic_graph_materialization_id,
    static_semantic_graph_node_id,
    static_semantic_graph_projection_id,
    static_semantic_graph_relation_id,
)
from chipchain.models import Architecture


ROOT = Path(__file__).resolve().parents[1]
GENERIC_FIXTURE = (
    ROOT
    / "tests/fixtures/phase10d/aarch64_generic_static_semantic_v1/"
    "aarch64_generic_static_semantic_v1.elf"
)
A77_FIXTURE = (
    ROOT
    / "tests/fixtures/phase10d/a_profile_static_semantic_a64/"
    "a_profile_static_semantic_a64.elf"
)


def _fact(
    *,
    architecture: Architecture = Architecture.ARM,
    address: str = "0x1000",
    instruction_bytes: str = "0x01020304",
    function_address: str | None = "0x1000",
    function_name: str | None = "owned_function",
    basic_block_address: str | None = "0x1000",
    operation: StaticSemanticOperation = StaticSemanticOperation.MEMORY_LOAD,
) -> StaticSemanticInstructionFact:
    return StaticSemanticInstructionFact.create(
        architecture=architecture,
        artifact_id="artifact:owned-semantic-graph",
        artifact_sha256="a" * 64,
        decoder_profile_id="owned-static-semantic-profile-v1",
        instruction_set=(
            "rv64gc" if architecture is Architecture.RISC_V else "aarch64"
        ),
        instruction_address=address,
        instruction_bytes=instruction_bytes,
        instruction_size=(len(instruction_bytes) - 2) // 2,
        function_address=function_address,
        function_name=function_name,
        basic_block_address=basic_block_address,
        operation=operation,
        attributes=[
            StaticSemanticAttribute(
                name=(
                    StaticSemanticAttributeName
                    .EFFECTIVE_MEMORY_TYPE_RESOLUTION
                ),
                value="requires_objective_translation_context",
            )
        ],
        fact_scope=(
            StaticSemanticFactScope
            .DECODED_STATIC_INSTRUCTION_SEMANTICS_ONLY
        ),
    )


def _inventory(
    facts: list[StaticSemanticInstructionFact],
    *,
    architecture: Architecture = Architecture.ARM,
) -> StaticSemanticInventory:
    return StaticSemanticInventory.create(
        architecture=architecture,
        artifact_id="artifact:owned-semantic-graph",
        artifact_sha256="a" * 64,
        decoder_profile_id="owned-static-semantic-profile-v1",
        instruction_set=(
            "rv64gc" if architecture is Architecture.RISC_V else "aarch64"
        ),
        analysis_scope=(
            StaticSemanticInventoryScope
            .PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY
        ),
        facts=facts,
        diagnostic_codes=[f"decoded_instruction_count:{len(facts)}"],
    )


def _four_case_inventory() -> StaticSemanticInventory:
    return _inventory(
        [
            _fact(address="0x1000"),
            _fact(
                address="0x2000",
                function_address="0x2000",
                function_name="owned_fallback_function",
                basic_block_address=None,
            ),
            _fact(
                address="0x3004",
                function_address=None,
                function_name=None,
                basic_block_address="0x3000",
            ),
            _fact(
                address="0x4000",
                function_address=None,
                function_name=None,
                basic_block_address=None,
            ),
        ]
    )


def _artifact(path: Path) -> ProgramArtifact:
    return ProgramArtifact(
        id="owned-synthetic-generic-aarch64-v1",
        architecture=Architecture.ARM,
        artifact_type="elf",
        path=str(path),
        fixture_identifier="phase10d-aarch64-generic-static-semantic-v1",
        metadata={"owned": True, "synthetic": True, "fixture": True},
    )


@pytest.fixture(scope="module")
def generic_inventory() -> StaticSemanticInventory:
    pytest.importorskip("angr")
    return AngrAArch64StaticSemanticDecoder().decode(
        _artifact(GENERIC_FIXTURE)
    )


@pytest.fixture(scope="module")
def generic_materialization(
    generic_inventory: StaticSemanticInventory,
) -> StaticSemanticGraphProjectionMaterialization:
    return project_static_semantic_inventory(generic_inventory)


def _recompute(payload: dict, field: str, id_function) -> None:
    payload[field] = id_function(
        {key: value for key, value in payload.items() if key != field}
    )


def _recompute_projection(payload: dict) -> None:
    _recompute(payload["projection"], "id", static_semantic_graph_projection_id)
    _recompute(payload, "id", static_semantic_graph_materialization_id)


def _replace_node_id(payload: dict, old_id: str, new_id: str) -> None:
    for relation in payload["projection"]["relations"]:
        changed = False
        if relation["source_node_id"] == old_id:
            relation["source_node_id"] = new_id
            changed = True
        if relation["target_node_id"] == old_id:
            relation["target_node_id"] = new_id
            changed = True
        if changed:
            _recompute(relation, "id", static_semantic_graph_relation_id)


def _semantic_nodes(projection: StaticSemanticGraphProjection):
    return [
        item
        for item in projection.nodes
        if item.kind
        is StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT
    ]


def test_public_api_accepts_exactly_one_inventory() -> None:
    signature = inspect.signature(project_static_semantic_inventory)

    assert list(signature.parameters) == ["inventory"]
    assert signature.parameters["inventory"].annotation == (
        "StaticSemanticInventory"
    )
    assert signature.return_annotation == (
        "StaticSemanticGraphProjectionMaterialization"
    )
    forbidden = ("artifact", "plan", "pattern", "predicate", "candidate")
    assert all(value not in signature.parameters for value in forbidden)


def test_exact_contracts_and_closed_vocabularies() -> None:
    assert PHASE10D_STATIC_SEMANTIC_GRAPH_PROJECTION_CONTRACT == (
        "phase10d_static_semantic_graph_projection_v1"
    )
    assert PHASE10D_STATIC_SEMANTIC_GRAPH_MATERIALIZATION_CONTRACT == (
        "phase10d_static_semantic_graph_materialization_v1"
    )
    assert list(StaticSemanticGraphNodeKind) == [
        StaticSemanticGraphNodeKind.FUNCTION,
        StaticSemanticGraphNodeKind.BASIC_BLOCK,
        StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT,
    ]
    assert list(StaticSemanticGraphRelationKind) == [
        StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK,
        StaticSemanticGraphRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT,
        StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT,
    ]
    assert list(StaticSemanticGraphProjectionScope) == [
        StaticSemanticGraphProjectionScope
        .PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY_GRAPH
    ]
    assert "cfg_successor" not in {
        item.value for item in StaticSemanticGraphRelationKind
    }


def test_production_dependency_and_schema_boundaries() -> None:
    paths = [
        ROOT / "src/chipchain/analysis/static_semantic_graph_models.py",
        ROOT / "src/chipchain/analysis/static_semantic_graph_projection.py",
    ]
    forbidden_imports = (
        "chipchain.hardware_trigger",
        "chipchain.analysis.aarch64_static_semantic_decoder",
        "angr",
        "capstone",
        "chipchain.knowledge",
        "chipchain.reasoning",
        "chipchain.runtime",
        "chipchain.verification",
        "chipchain.multi_agent",
    )
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        } | {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        assert not any(
            name == forbidden or name.startswith(f"{forbidden}.")
            for name in imported
            for forbidden in forbidden_imports
        )

    schema = str(
        StaticSemanticGraphProjectionMaterialization.model_json_schema()
    ).lower()
    for forbidden in (
        "aprofile",
        "cortex",
        "cve",
        "erratum",
        "pattern",
        "candidate",
        "triggerability",
        "attackchain",
        "crosslayerinteraction",
    ):
        assert forbidden not in schema


def test_all_four_partial_provenance_cases_project_exactly() -> None:
    materialization = project_static_semantic_inventory(
        _four_case_inventory()
    )
    projection = materialization.projection

    assert Counter(item.kind for item in projection.nodes) == {
        StaticSemanticGraphNodeKind.FUNCTION: 2,
        StaticSemanticGraphNodeKind.BASIC_BLOCK: 2,
        StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT: 4,
    }
    assert Counter(item.relation_kind for item in projection.relations) == {
        StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK: 1,
        StaticSemanticGraphRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT: 2,
        StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT: 1,
    }
    assert "uncontained_semantic_fact_node_count:1" in (
        projection.diagnostic_codes
    )
    assert "source_inventory_fact_count:4" in projection.diagnostic_codes
    assert "semantic_fact_node_count:4" in projection.diagnostic_codes


def test_function_without_block_has_direct_fact_containment() -> None:
    projection = project_static_semantic_inventory(
        _four_case_inventory()
    ).projection
    target = next(
        item
        for item in _semantic_nodes(projection)
        if item.instruction_address == "0x2000"
    )
    direct = [
        item
        for item in projection.relations
        if item.target_node_id == target.id
    ]

    assert target.function_address == "0x2000"
    assert target.basic_block_address is None
    assert len(direct) == 1
    assert direct[0].relation_kind is (
        StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT
    )
    assert not any(
        item.kind is StaticSemanticGraphNodeKind.BASIC_BLOCK
        and item.function_address == target.function_address
        for item in projection.nodes
    )


def test_block_without_function_does_not_invent_function() -> None:
    projection = project_static_semantic_inventory(
        _four_case_inventory()
    ).projection
    target = next(
        item
        for item in _semantic_nodes(projection)
        if item.instruction_address == "0x3004"
    )
    relation = next(
        item
        for item in projection.relations
        if item.target_node_id == target.id
    )
    source = next(
        item for item in projection.nodes if item.id == relation.source_node_id
    )

    assert target.function_address is None
    assert source.kind is StaticSemanticGraphNodeKind.BASIC_BLOCK
    assert source.function_address is None
    assert relation.relation_kind is (
        StaticSemanticGraphRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT
    )


def test_fact_without_function_or_block_remains_uncontained() -> None:
    projection = project_static_semantic_inventory(
        _four_case_inventory()
    ).projection
    target = next(
        item
        for item in _semantic_nodes(projection)
        if item.instruction_address == "0x4000"
    )

    assert target.function_address is None
    assert target.basic_block_address is None
    assert not any(
        item.target_node_id == target.id for item in projection.relations
    )


@pytest.mark.angr
def test_generic_aarch64_projection_is_lossless(
    generic_inventory: StaticSemanticInventory,
    generic_materialization: StaticSemanticGraphProjectionMaterialization,
) -> None:
    projection = generic_materialization.projection
    fact_node_by_source = {
        item.source_fact_ids[0]: item for item in _semantic_nodes(projection)
    }

    assert Counter(item.kind for item in projection.nodes) == {
        StaticSemanticGraphNodeKind.FUNCTION: 2,
        StaticSemanticGraphNodeKind.BASIC_BLOCK: 1,
        StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT: 11,
    }
    assert Counter(item.relation_kind for item in projection.relations) == {
        StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK: 1,
        StaticSemanticGraphRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT: 10,
        StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT: 1,
    }
    assert set(fact_node_by_source) == {
        item.id for item in generic_inventory.facts
    }
    for fact in generic_inventory.facts:
        node = fact_node_by_source[fact.id]
        assert (
            node.architecture,
            node.artifact_id,
            node.artifact_sha256,
            node.function_address,
            node.function_name,
            node.basic_block_address,
            node.instruction_address,
            node.instruction_bytes,
            node.instruction_size,
            node.operation,
            node.attributes,
            node.fact_scope,
        ) == (
            fact.architecture,
            fact.artifact_id,
            fact.artifact_sha256,
            fact.function_address,
            fact.function_name,
            fact.basic_block_address,
            fact.instruction_address,
            fact.instruction_bytes,
            fact.instruction_size,
            fact.operation,
            fact.attributes,
            fact.fact_scope,
        )
    assert {item.operation for item in fact_node_by_source.values()} == set(
        StaticSemanticOperation
    )


@pytest.mark.angr
def test_generic_eret_survives_without_fabricated_block(
    generic_materialization: StaticSemanticGraphProjectionMaterialization,
) -> None:
    projection = generic_materialization.projection
    eret = next(
        item
        for item in _semantic_nodes(projection)
        if item.operation is StaticSemanticOperation.EXCEPTION_RETURN
    )
    relation = next(
        item
        for item in projection.relations
        if item.target_node_id == eret.id
    )

    assert eret.instruction_address == "0x400034"
    assert eret.basic_block_address is None
    assert relation.relation_kind is (
        StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT
    )
    assert not any(
        item.kind is StaticSemanticGraphNodeKind.BASIC_BLOCK
        and item.function_address == eret.function_address
        for item in projection.nodes
    )


@pytest.mark.angr
def test_old_a77_inventory_reuses_same_projection() -> None:
    pytest.importorskip("angr")
    inventory = AngrAArch64StaticSemanticDecoder().decode(
        _artifact(A77_FIXTURE)
    )
    projection = project_static_semantic_inventory(inventory).projection
    facts = [
        (
            item.operation,
            {
                attribute.name: attribute.value
                for attribute in item.attributes
            }.get(StaticSemanticAttributeName.SYSTEM_REGISTER),
        )
        for item in _semantic_nodes(projection)
    ]

    assert facts == [
        (StaticSemanticOperation.MEMORY_LOAD, None),
        (StaticSemanticOperation.STORE_EXCLUSIVE, None),
        (StaticSemanticOperation.SYSTEM_REGISTER_READ, "par_el1"),
        (StaticSemanticOperation.MEMORY_STORE, None),
        (StaticSemanticOperation.LOAD_EXCLUSIVE, None),
        (StaticSemanticOperation.SYSTEM_REGISTER_WRITE, "par_el1"),
        (StaticSemanticOperation.SYSTEM_REGISTER_READ, "far_el1"),
    ]
    assert "source_inventory_fact_count:7" in projection.diagnostic_codes
    assert "semantic_fact_node_count:7" in projection.diagnostic_codes


def test_risc_v_variable_length_contract_uses_same_projection() -> None:
    fact = _fact(
        architecture=Architecture.RISC_V,
        instruction_bytes="0x0100",
    )
    inventory = _inventory([fact], architecture=Architecture.RISC_V)
    materialization = project_static_semantic_inventory(inventory)
    node = _semantic_nodes(materialization.projection)[0]

    assert materialization.projection.architecture is Architecture.RISC_V
    assert node.instruction_bytes == "0x0100"
    assert node.instruction_size == 2
    assert type(node) is StaticSemanticGraphNode


def test_function_name_conflict_fails_closed() -> None:
    inventory = _inventory(
        [
            _fact(address="0x1000", function_name="first_name"),
            _fact(address="0x1004", function_name="second_name"),
        ]
    )

    with pytest.raises(ValueError, match="conflicting function names"):
        project_static_semantic_inventory(inventory)


def test_materialization_is_deterministic_detached_and_ordered() -> None:
    inventory = _four_case_inventory()
    first = project_static_semantic_inventory(inventory)
    second = project_static_semantic_inventory(inventory)

    assert first == second
    assert first.id == second.id
    assert first.model_dump_json() == second.model_dump_json()
    assert first.projection.nodes == sorted(
        first.projection.nodes,
        key=lambda item: (
            {
                StaticSemanticGraphNodeKind.FUNCTION: 0,
                StaticSemanticGraphNodeKind.BASIC_BLOCK: 1,
                StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT: 2,
            }[item.kind],
            int(item.function_address or "0x0", 16),
            int(item.basic_block_address or "0x0", 16),
            int(item.instruction_address or "0x0", 16),
            item.id,
        ),
    )
    inventory.facts.clear()
    assert len(first.source_inventory_snapshot.facts) == 4


@pytest.mark.angr
def test_materialization_binds_exact_source_tuple(
    generic_materialization: StaticSemanticGraphProjectionMaterialization,
) -> None:
    source = generic_materialization.source_inventory_snapshot
    projection = generic_materialization.projection

    assert generic_materialization.source_inventory_id == source.id
    assert (
        projection.architecture,
        projection.artifact_id,
        projection.artifact_sha256,
        projection.source_inventory_id,
        projection.source_inventory_contract,
        projection.decoder_profile_id,
        projection.instruction_set,
        projection.source_inventory_scope,
    ) == (
        source.architecture,
        source.artifact_id,
        source.artifact_sha256,
        source.id,
        PHASE10D_STATIC_SEMANTIC_INVENTORY_CONTRACT,
        source.decoder_profile_id,
        source.instruction_set,
        source.analysis_scope,
    )


def test_duplicate_node_id_is_rejected() -> None:
    payload = project_static_semantic_inventory(
        _four_case_inventory()
    ).model_dump(mode="json")
    payload["projection"]["nodes"].append(
        dict(payload["projection"]["nodes"][0])
    )
    _recompute_projection(payload)

    with pytest.raises(ValidationError, match="node IDs must be unique"):
        StaticSemanticGraphProjectionMaterialization.model_validate(payload)


def test_duplicate_relation_id_is_rejected() -> None:
    payload = project_static_semantic_inventory(
        _four_case_inventory()
    ).model_dump(mode="json")
    payload["projection"]["relations"].append(
        dict(payload["projection"]["relations"][0])
    )
    _recompute_projection(payload)

    with pytest.raises(ValidationError, match="relation IDs must be unique"):
        StaticSemanticGraphProjectionMaterialization.model_validate(payload)


def test_dangling_relation_endpoint_is_rejected() -> None:
    payload = project_static_semantic_inventory(
        _four_case_inventory()
    ).model_dump(mode="json")
    relation = payload["projection"]["relations"][0]
    relation["target_node_id"] = "static-semantic-graph-node:missing"
    _recompute(relation, "id", static_semantic_graph_relation_id)
    _recompute_projection(payload)

    with pytest.raises(ValidationError, match="dangling endpoint"):
        StaticSemanticGraphProjectionMaterialization.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("artifact_id", "artifact:foreign", "node provenance mismatch"),
        ("architecture", Architecture.RISC_V.value, "architecture mismatch"),
    ],
)
def test_cross_provenance_node_is_rejected(
    field: str, value: str, message: str
) -> None:
    payload = project_static_semantic_inventory(
        _four_case_inventory()
    ).model_dump(mode="json")
    node = payload["projection"]["nodes"][-1]
    old_id = node["id"]
    node[field] = value
    _recompute(node, "id", static_semantic_graph_node_id)
    _replace_node_id(payload, old_id, node["id"])
    _recompute_projection(payload)

    with pytest.raises(ValidationError, match=message):
        StaticSemanticGraphProjectionMaterialization.model_validate(payload)


def test_incorrect_relation_source_support_is_rejected() -> None:
    payload = project_static_semantic_inventory(
        _four_case_inventory()
    ).model_dump(mode="json")
    relation = next(
        item
        for item in payload["projection"]["relations"]
        if item["relation_kind"] == "basic_block_contains_semantic_fact"
    )
    foreign_fact_id = payload["projection"]["nodes"][-1]["source_fact_ids"][0]
    assert foreign_fact_id not in relation["source_fact_ids"]
    relation["source_fact_ids"] = [foreign_fact_id]
    _recompute(relation, "id", static_semantic_graph_relation_id)
    _recompute_projection(payload)

    with pytest.raises(ValidationError, match="source support is not exact"):
        StaticSemanticGraphProjectionMaterialization.model_validate(payload)


def test_semantic_field_tamper_fails_exact_reprojection() -> None:
    payload = project_static_semantic_inventory(
        _four_case_inventory()
    ).model_dump(mode="json")
    node = next(
        item
        for item in payload["projection"]["nodes"]
        if item["kind"] == "semantic_instruction_fact"
    )
    old_id = node["id"]
    node["operation"] = "memory_store"
    _recompute(node, "id", static_semantic_graph_node_id)
    _replace_node_id(payload, old_id, node["id"])
    _recompute_projection(payload)

    with pytest.raises(ValidationError, match="deterministic reprojection"):
        StaticSemanticGraphProjectionMaterialization.model_validate(payload)


def test_relation_endpoint_kind_is_rejected() -> None:
    materialization = project_static_semantic_inventory(
        _four_case_inventory()
    )
    payload = materialization.model_dump(mode="json")
    relation = next(
        item
        for item in payload["projection"]["relations"]
        if item["relation_kind"] == "function_contains_basic_block"
    )
    relation["relation_kind"] = "function_contains_semantic_fact"
    _recompute(relation, "id", static_semantic_graph_relation_id)
    _recompute_projection(payload)

    with pytest.raises(ValidationError, match="relations are not exact"):
        StaticSemanticGraphProjectionMaterialization.model_validate(payload)


@pytest.mark.parametrize(
    "field", ["causal", "runtime_execution", "symbolic_feasibility"]
)
def test_relation_outcome_flags_cannot_be_true(field: str) -> None:
    payload = project_static_semantic_inventory(
        _four_case_inventory()
    ).model_dump(mode="json")
    relation = payload["projection"]["relations"][0]
    relation[field] = True
    _recompute(relation, "id", static_semantic_graph_relation_id)
    _recompute_projection(payload)

    with pytest.raises(ValidationError):
        StaticSemanticGraphProjectionMaterialization.model_validate(payload)


def test_path_like_identifiers_are_rejected() -> None:
    with pytest.raises(ValidationError, match="path-neutral"):
        StaticSemanticGraphNode.create(
            kind=StaticSemanticGraphNodeKind.FUNCTION,
            architecture=Architecture.ARM,
            artifact_id="/tmp/owned-artifact",
            artifact_sha256="a" * 64,
            source_inventory_id="static-semantic-inventory:owned",
            source_fact_ids=["static-semantic-instruction-fact:owned"],
            function_address="0x1000",
        )


def test_outcome_like_diagnostic_is_rejected() -> None:
    payload = project_static_semantic_inventory(
        _four_case_inventory()
    ).model_dump(mode="json")
    payload["projection"]["diagnostic_codes"].append("verified_result:1")
    _recompute_projection(payload)

    with pytest.raises(ValidationError, match="outcome-neutral"):
        StaticSemanticGraphProjectionMaterialization.model_validate(payload)


def test_empty_inventory_projects_without_backend_or_filesystem() -> None:
    materialization = project_static_semantic_inventory(_inventory([]))

    assert materialization.projection.nodes == []
    assert materialization.projection.relations == []
    assert materialization.projection.diagnostic_codes == [
        "basic_block_contains_semantic_fact_relation_count:0",
        "basic_block_node_count:0",
        "function_contains_basic_block_relation_count:0",
        "function_contains_semantic_fact_relation_count:0",
        "function_node_count:0",
        "semantic_fact_node_count:0",
        "source_inventory_fact_count:0",
        "uncontained_semantic_fact_node_count:0",
    ]


@pytest.mark.angr
def test_projection_has_no_cfg_or_outcome_semantics(
    generic_materialization: StaticSemanticGraphProjectionMaterialization,
) -> None:
    projection = generic_materialization.projection
    assert all(not item.causal for item in projection.relations)
    assert all(not item.runtime_execution for item in projection.relations)
    assert all(not item.symbolic_feasibility for item in projection.relations)
    serialized = projection.model_dump_json().lower()
    for forbidden in (
        "cfg_successor",
        "runtime_executed",
        "triggerable",
        "verified",
        "vulnerable",
    ):
        assert forbidden not in serialized
