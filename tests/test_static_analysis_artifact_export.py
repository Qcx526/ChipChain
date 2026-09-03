"""Presentation-only golden tests for frozen static-analysis artifacts."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from chipchain.analysis import (
    AngrAArch64StaticProgramStructureExtractor,
    AngrAArch64StaticSemanticDecoder,
    ProgramArtifact,
    StaticProgramCfgSemantics,
    StaticProgramFunctionCfg,
    StaticProgramStructureInventory,
    StaticSemanticFactScope,
    StaticSemanticGraphNodeKind,
    StaticSemanticGraphRelationKind,
    StaticSemanticInstructionFact,
    StaticSemanticInventory,
    StaticSemanticInventoryScope,
    StaticSemanticOperation,
    escape_dot_string,
    export_static_analysis_artifact_bundle,
    project_static_semantic_inventory,
    render_dot_to_svg_if_available,
    render_static_analysis_inspection_summary_markdown,
    render_static_program_structure_graph_dot,
    render_static_program_structure_inventory_json,
    render_static_program_structure_summary_markdown,
    render_static_semantic_graph_dot,
    render_static_semantic_graph_json,
    render_static_semantic_inventory_json,
    render_static_semantic_summary_markdown,
)
from chipchain.analysis import static_analysis_artifact_export as export_module
from chipchain.models import Architecture


pytest.importorskip("angr")
pytestmark = pytest.mark.angr

ROOT = Path(__file__).resolve().parents[1]
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
EXAMPLES = ROOT / "examples/phase10d/static_analysis_artifacts"
TEXT_FILES = {
    "semantic_inventory.json",
    "semantic_graph.json",
    "semantic_summary.md",
    "semantic_graph.dot",
    "structure_inventory.json",
    "structure_summary.md",
    "structure_graph.dot",
    "inspection_summary.md",
    "manifest.json",
}


def _artifact(path: Path, artifact_id: str, fixture_id: str) -> ProgramArtifact:
    return ProgramArtifact(
        id=artifact_id,
        architecture=Architecture.ARM,
        artifact_type="elf",
        path=str(path),
        fixture_identifier=fixture_id,
    )


def _sources(path: Path, artifact_id: str, fixture_id: str):
    artifact = _artifact(path, artifact_id, fixture_id)
    semantic = AngrAArch64StaticSemanticDecoder().decode(artifact)
    graph = project_static_semantic_inventory(semantic)
    structure = AngrAArch64StaticProgramStructureExtractor().extract(artifact)
    return semantic, graph, structure


@pytest.fixture(scope="module")
def generic_sources():
    return _sources(
        GENERIC_FIXTURE,
        "owned-synthetic-generic-aarch64-v1",
        "phase10d-aarch64-generic-static-semantic-v1",
    )


@pytest.fixture(scope="module")
def structure_sources():
    return _sources(
        STRUCTURE_FIXTURE,
        "owned-synthetic-aarch64-static-program-structure-v1",
        "phase10d-aarch64-static-program-structure-v1",
    )


def _rendered(sources) -> dict[str, str]:
    semantic, graph, structure = sources
    return {
        "semantic_inventory.json": render_static_semantic_inventory_json(
            semantic
        ),
        "semantic_graph.json": render_static_semantic_graph_json(graph),
        "semantic_summary.md": render_static_semantic_summary_markdown(
            semantic, graph
        ),
        "semantic_graph.dot": render_static_semantic_graph_dot(graph),
        "structure_inventory.json": (
            render_static_program_structure_inventory_json(structure)
        ),
        "structure_summary.md": (
            render_static_program_structure_summary_markdown(structure)
        ),
        "structure_graph.dot": (
            render_static_program_structure_graph_dot(structure)
        ),
        "inspection_summary.md": (
            render_static_analysis_inspection_summary_markdown(
                semantic, graph, structure
            )
        ),
    }


def _synthetic_inspection_sources(
    *,
    basic_block_address: str | None,
    structure_artifact_id: str = "owned-synthetic-inspection-v1",
):
    artifact_id = "owned-synthetic-inspection-v1"
    artifact_sha256 = "a" * 64
    instruction_address = "0x500010"
    function_address = "0x500000"
    instruction_set = "aarch64"
    fact = StaticSemanticInstructionFact.create(
        architecture=Architecture.ARM,
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        decoder_profile_id="owned-synthetic-decoder-v1",
        instruction_set=instruction_set,
        instruction_address=instruction_address,
        instruction_bytes="0x200040f9",
        instruction_size=4,
        function_address=function_address,
        function_name="owned_synthetic_inspection",
        basic_block_address=basic_block_address,
        operation=StaticSemanticOperation.MEMORY_LOAD,
        fact_scope=(
            StaticSemanticFactScope
            .DECODED_STATIC_INSTRUCTION_SEMANTICS_ONLY
        ),
    )
    semantic = StaticSemanticInventory.create(
        architecture=Architecture.ARM,
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        decoder_profile_id=fact.decoder_profile_id,
        instruction_set=instruction_set,
        analysis_scope=(
            StaticSemanticInventoryScope
            .PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY
        ),
        facts=[fact],
        diagnostic_codes=["semantic_fact_count:1"],
    )
    graph = project_static_semantic_inventory(semantic)
    function = StaticProgramFunctionCfg.create(
        architecture=Architecture.ARM,
        artifact_id=structure_artifact_id,
        artifact_sha256=artifact_sha256,
        analyzer_profile_id="owned-synthetic-structure-v1",
        instruction_set=instruction_set,
        function_address=function_address,
        function_name="owned_synthetic_inspection",
        basic_block_addresses=[instruction_address],
        directed_edges=[],
        cfg_semantics=(
            StaticProgramCfgSemantics
            .FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1
        ),
    )
    structure = StaticProgramStructureInventory.create(
        architecture=Architecture.ARM,
        artifact_id=structure_artifact_id,
        artifact_sha256=artifact_sha256,
        analyzer_profile_id=function.analyzer_profile_id,
        instruction_set=instruction_set,
        functions=[function],
    )
    return semantic, graph, structure


def test_canonical_json_is_exact_and_deterministic(generic_sources) -> None:
    semantic, graph, structure = generic_sources
    rendered = _rendered(generic_sources)

    assert json.loads(rendered["semantic_inventory.json"]) == (
        semantic.model_dump(mode="json")
    )
    assert json.loads(rendered["semantic_graph.json"]) == (
        graph.model_dump(mode="json")
    )
    assert json.loads(rendered["structure_inventory.json"]) == (
        structure.model_dump(mode="json")
    )
    assert all(
        value.endswith("\n")
        and not value.endswith("\n\n")
        for name, value in rendered.items()
        if name.endswith(".json")
    )


def test_rendering_ten_times_has_one_sha(generic_sources) -> None:
    hashes = {
        hashlib.sha256(
            "".join(_rendered(generic_sources).values()).encode("utf-8")
        ).hexdigest()
        for _ in range(10)
    }

    assert len(hashes) == 1


def test_rendering_does_not_mutate_sources(generic_sources) -> None:
    before = tuple(item.model_dump_json() for item in generic_sources)

    _rendered(generic_sources)

    assert tuple(item.model_dump_json() for item in generic_sources) == before


def test_semantic_summary_has_exact_operation_and_graph_counts(
    generic_sources,
) -> None:
    summary = _rendered(generic_sources)["semantic_summary.md"]

    assert "- Semantic fact count: 11" in summary
    assert "| `memory_barrier` | 2 |" in summary
    assert "| `exception_return` | 1 |" in summary
    assert "- FUNCTION: 2" in summary
    assert "- BASIC_BLOCK: 1" in summary
    assert "- SEMANTIC_INSTRUCTION_FACT: 11" in summary
    assert "- FUNCTION_CONTAINS_BASIC_BLOCK: 1" in summary
    assert "- BASIC_BLOCK_CONTAINS_SEMANTIC_FACT: 10" in summary
    assert "- FUNCTION_CONTAINS_SEMANTIC_FACT: 1" in summary
    assert "- Uncontained semantic fact count: 0" in summary


def test_structure_summary_has_exact_counts(structure_sources) -> None:
    summary = _rendered(structure_sources)["structure_summary.md"]

    assert "- Function count: 3" in summary
    assert "- Basic-block count: 5" in summary
    assert "- Directed CFG-edge count: 3" in summary
    assert "- Zero-edge function count: 1" in summary
    assert "`0x400000` -> `0x400004`" in summary
    assert "`0x400018` -> `0x400018`" in summary


def test_semantic_dot_contains_only_exact_frozen_relations(
    generic_sources,
) -> None:
    _semantic, graph, _structure = generic_sources
    dot = render_static_semantic_graph_dot(graph)
    edge_lines = [line for line in dot.splitlines() if " -> " in line]
    node_names = {
        node.id: f"node_{index}"
        for index, node in enumerate(graph.projection.nodes)
    }

    assert len(edge_lines) == len(graph.projection.relations) == 12
    assert all(
        "contains block" in line or "contains semantic fact" in line
        for line in edge_lines
    )
    for relation in graph.projection.relations:
        expected = (
            f"{node_names[relation.source_node_id]} -> "
            f"{node_names[relation.target_node_id]}"
        )
        assert any(expected in line for line in edge_lines)


def test_eret_direct_function_containment_remains_visible(
    generic_sources,
) -> None:
    _semantic, graph, _structure = generic_sources
    nodes = graph.projection.nodes
    eret = next(
        node
        for node in nodes
        if node.kind
        is StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT
        and node.instruction_address == "0x400034"
    )
    function = next(
        node
        for node in nodes
        if node.kind is StaticSemanticGraphNodeKind.FUNCTION
        and node.function_address == "0x400034"
    )
    relation = next(
        item
        for item in graph.projection.relations
        if item.source_node_id == function.id and item.target_node_id == eret.id
    )
    dot = render_static_semantic_graph_dot(graph)

    assert relation.relation_kind is (
        StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT
    )
    assert "exception_return\\n0x400034" in dot
    assert 'label="contains semantic fact"' in dot


def test_structure_dot_contains_exact_cfg_edges_and_self_loop(
    structure_sources,
) -> None:
    dot = _rendered(structure_sources)["structure_graph.dot"]
    edge_lines = [line for line in dot.splitlines() if " -> " in line]

    assert edge_lines == [
        '  block_0_0 -> block_0_1 [label="static CFG", color="navy"];',
        '  block_0_0 -> block_0_2 [label="static CFG", color="navy"];',
        '  block_2_0 -> block_2_0 [label="static CFG", color="navy"];',
    ]
    assert "block_0_1 -> block_0_2" not in dot


def test_eret_missing_cfg_difference_is_explicit(generic_sources) -> None:
    summary = _rendered(generic_sources)["inspection_summary.md"]

    assert "instruction_address = `0x400034`" in summary
    assert "function_address = `0x400034`" in summary
    assert "basic_block_address = `None`" in summary
    assert "structure function `0x400034` = `absent`" in summary
    assert "semantic basic-block provenance = `not provided`" in summary
    assert "structure block `0x400034`" not in summary
    assert "Instruction Address != Basic-Block Provenance." in summary
    assert "No function-level CFG support was independently recovered" in summary


def test_cross_source_coverage_stops_at_provenance_mismatch() -> None:
    semantic, graph, structure = _synthetic_inspection_sources(
        basic_block_address="0x500010",
        structure_artifact_id="owned-synthetic-other-artifact-v1",
    )

    summary = render_static_analysis_inspection_summary_markdown(
        semantic, graph, structure
    )

    assert (
        "| `artifact_id` | `owned-synthetic-inspection-v1` | "
        "`owned-synthetic-other-artifact-v1` | `false` |"
    ) in summary
    assert (
        "Cross-source structural coverage comparison was not performed"
        in summary
    )
    assert "structure function `0x500000`" not in summary
    assert "structure block `0x500010`" not in summary


def test_missing_block_provenance_never_uses_instruction_address() -> None:
    semantic, graph, structure = _synthetic_inspection_sources(
        basic_block_address=None
    )

    summary = render_static_analysis_inspection_summary_markdown(
        semantic, graph, structure
    )

    assert "instruction_address = `0x500010`" in summary
    assert "basic_block_address = `None`" in summary
    assert "structure function `0x500000` = `present`" in summary
    assert "semantic basic-block provenance = `not provided`" in summary
    assert "structure block `0x500010`" not in summary
    assert "Instruction Address != Basic-Block Provenance." in summary


def test_exact_declared_block_provenance_remains_comparable() -> None:
    semantic, graph, structure = _synthetic_inspection_sources(
        basic_block_address="0x500010"
    )

    summary = render_static_analysis_inspection_summary_markdown(
        semantic, graph, structure
    )

    assert "No source-coverage differences observed." in summary
    assert "semantic basic-block provenance = `not provided`" not in summary


def test_dot_escaping_is_explicit() -> None:
    assert escape_dot_string('quote" slash\\ line\nnext') == (
        'quote\\" slash\\\\ line\\nnext'
    )


def test_export_manifest_hashes_all_text_outputs(
    generic_sources,
    tmp_path: Path,
) -> None:
    semantic, graph, structure = generic_sources
    result = export_static_analysis_artifact_bundle(
        semantic_inventory=semantic,
        semantic_graph_materialization=graph,
        structure_inventory=structure,
        output_directory=tmp_path,
        include_svg=False,
    )
    manifest = json.loads((tmp_path / "manifest.json").read_text())

    assert set(result.files) == TEXT_FILES
    assert result.svg_files == ()
    assert set(manifest["files"]) == TEXT_FILES - {"manifest.json"}
    for filename, provenance in manifest["files"].items():
        raw = (tmp_path / filename).read_bytes()
        assert provenance == {
            "byte_size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    assert "manifest.json" not in manifest["files"]


def test_graphviz_absence_does_not_fail_export(
    generic_sources,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    semantic, graph, structure = generic_sources
    monkeypatch.setattr(export_module.shutil, "which", lambda _name: None)

    result = export_static_analysis_artifact_bundle(
        semantic_inventory=semantic,
        semantic_graph_materialization=graph,
        structure_inventory=structure,
        output_directory=tmp_path,
    )

    assert result.svg_files == ()
    assert not list(tmp_path.glob("*.svg"))


def test_svg_subprocess_uses_argument_list_and_no_shell(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, dict]] = []

    def fake_run(arguments, **values):
        calls.append((arguments, values))
        return SimpleNamespace(returncode=0, stdout=b"<svg/>")

    monkeypatch.setattr(
        export_module.shutil, "which", lambda _name: "/owned/bin/dot"
    )
    monkeypatch.setattr(export_module.subprocess, "run", fake_run)
    output = tmp_path / "graph.svg"

    assert render_dot_to_svg_if_available("digraph {}\n", output)
    assert output.read_bytes() == b"<svg/>"
    assert calls[0][0] == ["/owned/bin/dot", "-Tsvg"]
    assert calls[0][1]["shell"] is False


@pytest.mark.parametrize(
    ("directory", "sources"),
    [
        ("generic_semantic", "generic_sources"),
        ("owned_structure", "structure_sources"),
    ],
)
def test_checked_in_golden_bundle_matches_regeneration(
    directory: str,
    sources: str,
    request: pytest.FixtureRequest,
    tmp_path: Path,
) -> None:
    semantic, graph, structure = request.getfixturevalue(sources)
    result = export_static_analysis_artifact_bundle(
        semantic_inventory=semantic,
        semantic_graph_materialization=graph,
        structure_inventory=structure,
        output_directory=tmp_path,
        include_svg=False,
    )
    golden = EXAMPLES / directory

    assert set(result.files) == TEXT_FILES
    assert {path.name for path in golden.iterdir()} == TEXT_FILES
    for filename in sorted(TEXT_FILES):
        assert (tmp_path / filename).read_bytes() == (
            golden / filename
        ).read_bytes()


def test_outputs_have_no_machine_or_nondeterministic_fields(
    generic_sources,
) -> None:
    rendered = "\n".join(_rendered(generic_sources).values()).lower()

    assert str(ROOT).lower() not in rendered
    for forbidden in (
        "generated_at",
        "timestamp",
        "hostname",
        "username",
        "random_uuid",
    ):
        assert forbidden not in rendered


def test_presentation_language_does_not_upgrade_source_meaning(
    generic_sources,
) -> None:
    rendered = _rendered(generic_sources)
    presentation = "\n".join(
        value
        for filename, value in rendered.items()
        if filename.endswith((".md", ".dot"))
    ).lower()

    for allowed_boundary in (
        "static containment != runtime execution.",
        "static containment != causality.",
        "inspection summary != vulnerability verdict.",
    ):
        presentation = presentation.replace(allowed_boundary, "")
    for prohibited in (
        "executed",
        "runtime reached",
        "caused",
        "triggered",
        "verified",
        "vulnerable",
        "attack chain",
        "exploit feasible",
    ):
        assert prohibited not in presentation


def test_pure_renderer_dependency_boundary() -> None:
    path = (
        ROOT
        / "src/chipchain/analysis/static_analysis_artifact_export.py"
    )
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
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
    forbidden = (
        "angr",
        "capstone",
        "chipchain.hardware_trigger",
        "chipchain.knowledge",
        "chipchain.reasoning",
        "chipchain.runtime",
        "chipchain.verification",
        "chipchain.multi_agent",
        "chipchain.analysis.aarch64_static_semantic_decoder",
        "chipchain.analysis.aarch64_static_program_structure_extractor",
    )

    assert not any(
        name == item or name.startswith(f"{item}.")
        for name in imported
        for item in forbidden
    )
