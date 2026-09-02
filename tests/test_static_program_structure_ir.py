"""Contracts for the plan-independent static program-structure IR."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from pydantic import ValidationError
import pytest

from chipchain.analysis import (
    PHASE10D_STATIC_PROGRAM_CFG_EDGE_CONTRACT,
    PHASE10D_STATIC_PROGRAM_FUNCTION_CFG_CONTRACT,
    PHASE10D_STATIC_PROGRAM_STRUCTURE_INVENTORY_CONTRACT,
    StaticProgramCfgEdge,
    StaticProgramCfgSemantics,
    StaticProgramFunctionCfg,
    StaticProgramStructureInventory,
    StaticProgramStructureInventoryScope,
    static_program_basic_block_source_id,
    static_program_cfg_edge_id,
    static_program_function_cfg_id,
    static_program_structure_diagnostics,
    static_program_structure_inventory_id,
)
from chipchain.models import Architecture


ROOT = Path(__file__).resolve().parents[1]
CFG_SEMANTICS = (
    StaticProgramCfgSemantics
    .FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1
)


def _provenance(
    *, architecture: Architecture = Architecture.ARM
) -> dict[str, object]:
    return {
        "architecture": architecture,
        "artifact_id": "artifact:owned-static-program-structure",
        "artifact_sha256": "a" * 64,
        "analyzer_profile_id": "owned-objective-structure-analyzer-v1",
        "instruction_set": (
            "rv64gc" if architecture is Architecture.RISC_V else "aarch64"
        ),
    }


def _edge(
    source: str = "0x1000",
    target: str = "0x1010",
    *,
    function_address: str = "0x1000",
    architecture: Architecture = Architecture.ARM,
    **overrides: object,
) -> StaticProgramCfgEdge:
    values = {
        **_provenance(architecture=architecture),
        "function_address": function_address,
        "source_basic_block_address": source,
        "target_basic_block_address": target,
        "cfg_semantics": CFG_SEMANTICS,
        **overrides,
    }
    return StaticProgramCfgEdge.create(**values)


def _function(
    *,
    function_address: str = "0x1000",
    function_name: str | None = "owned_structure_function",
    blocks: list[str] | None = None,
    edges: list[StaticProgramCfgEdge] | None = None,
    architecture: Architecture = Architecture.ARM,
    **overrides: object,
) -> StaticProgramFunctionCfg:
    values = {
        **_provenance(architecture=architecture),
        "function_address": function_address,
        "function_name": function_name,
        "basic_block_addresses": (
            ["0x1000", "0x1010"] if blocks is None else blocks
        ),
        "directed_edges": (
            [_edge(function_address=function_address, architecture=architecture)]
            if edges is None
            else edges
        ),
        "cfg_semantics": CFG_SEMANTICS,
        **overrides,
    }
    return StaticProgramFunctionCfg.create(**values)


def _inventory(
    functions: list[StaticProgramFunctionCfg],
    *,
    architecture: Architecture = Architecture.ARM,
    **overrides: object,
) -> StaticProgramStructureInventory:
    values = {
        **_provenance(architecture=architecture),
        "functions": functions,
        **overrides,
    }
    return StaticProgramStructureInventory.create(**values)


def _recompute(payload: dict, field: str, id_function) -> None:
    payload[field] = id_function(
        {key: value for key, value in payload.items() if key != field}
    )


def test_exact_contract_versions_and_closed_enums() -> None:
    assert PHASE10D_STATIC_PROGRAM_CFG_EDGE_CONTRACT == (
        "phase10d_static_program_cfg_edge_v1"
    )
    assert PHASE10D_STATIC_PROGRAM_FUNCTION_CFG_CONTRACT == (
        "phase10d_static_program_function_cfg_v1"
    )
    assert PHASE10D_STATIC_PROGRAM_STRUCTURE_INVENTORY_CONTRACT == (
        "phase10d_static_program_structure_inventory_v1"
    )
    assert list(StaticProgramCfgSemantics) == [CFG_SEMANTICS]
    assert list(StaticProgramStructureInventoryScope) == [
        StaticProgramStructureInventoryScope
        .PARTIAL_OBJECTIVE_FUNCTION_LOCAL_CFG_INVENTORY
    ]


def test_v1_schema_locks_exact_cfg_semantics_and_inventory_scope() -> None:
    edge_schema = StaticProgramCfgEdge.model_json_schema()
    function_schema = StaticProgramFunctionCfg.model_json_schema()
    inventory_schema = StaticProgramStructureInventory.model_json_schema()

    assert edge_schema["properties"]["cfg_semantics"] == {
        "const": (
            "function_local_directed_basic_block_reachability_v1"
        ),
        "title": "Cfg Semantics",
        "type": "string",
    }
    assert function_schema["properties"]["cfg_semantics"] == {
        "const": (
            "function_local_directed_basic_block_reachability_v1"
        ),
        "title": "Cfg Semantics",
        "type": "string",
    }
    assert inventory_schema["properties"]["analysis_scope"] == {
        "const": "partial_objective_function_local_cfg_inventory",
        "title": "Analysis Scope",
        "type": "string",
    }


def test_public_models_are_contract_only() -> None:
    signatures = {
        model.__name__: inspect.signature(model.create)
        for model in (
            StaticProgramCfgEdge,
            StaticProgramFunctionCfg,
            StaticProgramStructureInventory,
        )
    }
    schema = str(StaticProgramStructureInventory.model_json_schema()).lower()

    assert set(signatures) == {
        "StaticProgramCfgEdge",
        "StaticProgramFunctionCfg",
        "StaticProgramStructureInventory",
    }
    for forbidden in (
        "programartifact",
        "semanticinstruction",
        "instruction_bytes",
        "instruction_word",
        "pattern",
        "candidate",
    ):
        assert forbidden not in schema


def test_dependency_firewall_and_neutral_schema() -> None:
    path = ROOT / "src/chipchain/analysis/static_program_structure_models.py"
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
    forbidden_imports = (
        "chipchain.hardware_trigger",
        "chipchain.analysis.aarch64_static_semantic_decoder",
        "chipchain.analysis.static_semantic_graph_projection",
        "angr",
        "capstone",
        "chipchain.knowledge",
        "chipchain.reasoning",
        "chipchain.runtime",
        "chipchain.verification",
        "chipchain.multi_agent",
    )
    assert not any(
        name == forbidden or name.startswith(f"{forbidden}.")
        for name in imported
        for forbidden in forbidden_imports
    )

    schema = str(StaticProgramStructureInventory.model_json_schema()).lower()
    for forbidden in (
        "cve",
        "erratum",
        "pattern",
        "candidate",
        "triggerability",
        "attackchain",
        "crosslayerinteraction",
        "aprofile",
        "cortex",
    ):
        assert forbidden not in schema


def test_edge_is_canonical_deterministic_and_non_outcome() -> None:
    first = _edge(source="0x00001000", target="0x00001010")
    second = _edge(source="0x1000", target="0x00001010")

    assert first == second
    assert first.id == second.id
    assert first.source_basic_block_address == "0x1000"
    assert first.target_basic_block_address == "0x1010"
    assert first.contract == PHASE10D_STATIC_PROGRAM_CFG_EDGE_CONTRACT
    assert not first.causal
    assert not first.runtime_execution
    assert not first.symbolic_feasibility


def test_self_loop_edge_is_allowed() -> None:
    edge = _edge(source="0x1000", target="0x1000")
    function = _function(blocks=["0x1000"], edges=[edge])

    assert function.directed_edges == [edge]
    assert edge.source_basic_block_address == edge.target_basic_block_address


def test_function_cfg_is_ordered_and_binds_exact_edges() -> None:
    first = _edge(source="0x1000", target="0x1020")
    second = _edge(source="0x1020", target="0x1010")
    function = _function(
        blocks=["0x1020", "0x001000", "0x1010"],
        edges=[second, first],
    )

    assert function.basic_block_addresses == ["0x1000", "0x1010", "0x1020"]
    assert function.directed_edges == [first, second]
    assert function.contract == PHASE10D_STATIC_PROGRAM_FUNCTION_CFG_CONTRACT
    assert function.function_name == "owned_structure_function"


def test_basic_block_source_id_is_canonical_and_deterministic() -> None:
    function = _function()

    first = static_program_basic_block_source_id(function.id, "0x001000")
    second = static_program_basic_block_source_id(function.id, "0x1000")
    foreign = static_program_basic_block_source_id(
        _function(function_name=None).id, "0x1000"
    )

    assert first == second
    assert first.startswith("static-program-basic-block-source:")
    assert first != foreign


def test_inventory_diagnostics_are_exact_and_derived() -> None:
    first = _function()
    second = _function(
        function_address="0x2000",
        function_name=None,
        blocks=["0x2000"],
        edges=[],
    )
    inventory = _inventory([second, first])

    assert inventory.functions == [first, second]
    assert inventory.contract == (
        PHASE10D_STATIC_PROGRAM_STRUCTURE_INVENTORY_CONTRACT
    )
    assert inventory.analysis_scope is (
        StaticProgramStructureInventoryScope
        .PARTIAL_OBJECTIVE_FUNCTION_LOCAL_CFG_INVENTORY
    )
    assert inventory.diagnostic_codes == [
        "basic_block_count:3",
        "directed_cfg_edge_count:1",
        "function_cfg_count:2",
        "zero_edge_function_count:1",
    ]
    assert inventory.diagnostic_codes == static_program_structure_diagnostics(
        inventory.functions
    )


def test_arm_and_risc_v_use_the_same_contracts() -> None:
    arm = _inventory([_function()])
    riscv_function = _function(
        architecture=Architecture.RISC_V,
        function_address="0x00000000000100",
        blocks=["0x100", "0x00000102"],
        edges=[
            _edge(
                architecture=Architecture.RISC_V,
                function_address="0x100",
                source="0x100",
                target="0x102",
            )
        ],
    )
    riscv = _inventory(
        [riscv_function], architecture=Architecture.RISC_V
    )

    assert type(arm) is type(riscv) is StaticProgramStructureInventory
    assert type(arm.functions[0]) is type(riscv.functions[0])
    assert type(arm.functions[0].directed_edges[0]) is type(
        riscv.functions[0].directed_edges[0]
    )
    assert riscv.functions[0].function_address == "0x100"
    assert riscv.functions[0].basic_block_addresses == ["0x100", "0x102"]
    assert riscv.instruction_set == "rv64gc"


def test_inventory_identity_is_deterministic_and_detached() -> None:
    edge = _edge()
    edge_inputs = [edge]
    function = _function(edges=edge_inputs)
    function_inputs = [function]
    first = _inventory(function_inputs)
    second = _inventory([_function()])

    assert first == second
    assert first.id == second.id
    assert first.model_dump_json() == second.model_dump_json()
    edge_inputs.clear()
    function_inputs.clear()
    assert len(first.functions) == 1
    assert len(first.functions[0].directed_edges) == 1


def test_empty_inventory_is_valid() -> None:
    inventory = _inventory([])

    assert inventory.functions == []
    assert inventory.diagnostic_codes == [
        "basic_block_count:0",
        "directed_cfg_edge_count:0",
        "function_cfg_count:0",
        "zero_edge_function_count:0",
    ]


def test_duplicate_function_address_is_rejected() -> None:
    with pytest.raises(ValidationError, match="function addresses must be unique"):
        _inventory([_function(), _function(function_name=None)])


def test_duplicate_block_after_canonicalization_is_rejected() -> None:
    with pytest.raises(ValidationError, match="block addresses must be unique"):
        _function(blocks=["0x1000", "0x00001000"], edges=[])


def test_function_cfg_requires_at_least_one_basic_block() -> None:
    with pytest.raises(ValidationError):
        _function(blocks=[], edges=[])


def test_duplicate_edge_id_is_rejected() -> None:
    edge = _edge()
    with pytest.raises(ValidationError, match="edge IDs must be unique"):
        _function(edges=[edge, edge])


def test_duplicate_edge_endpoint_pair_is_rejected() -> None:
    first = _edge()
    second = _edge(analyzer_profile_id="foreign-objective-analyzer-v1")
    with pytest.raises(ValidationError, match="endpoint pairs must be unique"):
        _function(edges=[first, second])


def test_edge_endpoint_outside_function_is_rejected() -> None:
    with pytest.raises(ValidationError, match="outside function blocks"):
        _function(edges=[_edge(target="0x9990")])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_id", "artifact:foreign-structure"),
        ("architecture", Architecture.RISC_V),
        ("analyzer_profile_id", "foreign-objective-analyzer-v1"),
        ("instruction_set", "foreign-isa"),
        ("function_address", "0x2000"),
    ],
)
def test_cross_provenance_edge_is_rejected(field: str, value: object) -> None:
    edge = _edge(**{field: value})

    with pytest.raises(ValidationError, match="crosses function provenance"):
        _function(edges=[edge])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_id", "artifact:foreign-structure"),
        ("architecture", Architecture.RISC_V),
        ("analyzer_profile_id", "foreign-objective-analyzer-v1"),
        ("instruction_set", "foreign-isa"),
    ],
)
def test_cross_provenance_function_is_rejected(
    field: str, value: object
) -> None:
    function = _function(edges=[], **{field: value})

    with pytest.raises(
        ValidationError, match="crosses structure inventory provenance"
    ):
        _inventory([function])


@pytest.mark.parametrize(
    ("factory", "id_function", "message"),
    [
        (_edge, static_program_cfg_edge_id, "edge ID mismatch"),
        (_function, static_program_function_cfg_id, "function CFG ID mismatch"),
        (
            lambda: _inventory([_function()]),
            static_program_structure_inventory_id,
            "inventory ID mismatch",
        ),
    ],
)
def test_tampered_deterministic_id_is_rejected(
    factory, id_function, message: str
) -> None:
    value = factory()
    payload = value.model_dump(mode="json")
    payload["id"] = id_function({"tampered": True})

    with pytest.raises(ValidationError, match=message):
        type(value).model_validate(payload)


@pytest.mark.parametrize(
    "field", ["causal", "runtime_execution", "symbolic_feasibility"]
)
def test_edge_outcome_flags_cannot_be_true(field: str) -> None:
    with pytest.raises(ValidationError):
        _edge(**{field: True})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_id", "/tmp/owned-artifact"),
        ("analyzer_profile_id", "file:/tmp/analyzer"),
        ("instruction_set", "~/owned-isa"),
    ],
)
def test_path_like_provenance_is_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError, match="path-neutral"):
        _edge(**{field: value})


def test_path_like_basic_block_source_input_is_rejected() -> None:
    with pytest.raises(ValueError, match="path-neutral"):
        static_program_basic_block_source_id("file:/tmp/function", "0x1000")


def test_outcome_like_provenance_is_rejected() -> None:
    with pytest.raises(ValidationError, match="outcome-neutral"):
        _edge(analyzer_profile_id="verified-analyzer-profile")


def test_outcome_like_diagnostic_is_rejected() -> None:
    payload = _inventory([_function()]).model_dump(mode="json")
    payload["diagnostic_codes"].append("verified:1")
    _recompute(payload, "id", static_program_structure_inventory_id)

    with pytest.raises(ValidationError, match="outcome-neutral"):
        StaticProgramStructureInventory.model_validate(payload)


def test_incorrect_diagnostics_are_rejected() -> None:
    with pytest.raises(ValidationError, match="diagnostics do not match"):
        _inventory(
            [_function()],
            diagnostic_codes=[
                "basic_block_count:0",
                "directed_cfg_edge_count:0",
                "function_cfg_count:0",
                "zero_edge_function_count:0",
            ],
        )
