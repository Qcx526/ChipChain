"""Golden tests for fused static behavior presentation artifacts."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

from chipchain.analysis import (
    AngrAArch64StaticProgramStructureExtractor,
    AngrAArch64StaticSemanticDecoder,
    ProgramArtifact,
    StaticFusedBehaviorNodeKind,
    StaticFusedBehaviorRelationKind,
    export_static_fused_behavior_artifact_bundle,
    fuse_static_semantic_and_program_structure,
    project_static_semantic_inventory,
    render_static_fused_behavior_graph_dot,
    render_static_fused_behavior_graph_json,
    render_static_fused_behavior_summary_markdown,
)
from chipchain.analysis import (
    static_fused_behavior_artifact_export as export_module,
)
from chipchain.models import Architecture


pytest.importorskip("angr")
pytestmark = pytest.mark.angr

ROOT = Path(__file__).resolve().parents[1]
FUSION_FIXTURE = (
    ROOT
    / "tests/fixtures/phase10d/aarch64_static_fused_behavior_v1/"
    "aarch64_static_fused_behavior_v1.elf"
)
GENERIC_FIXTURE = (
    ROOT
    / "tests/fixtures/phase10d/aarch64_generic_static_semantic_v1/"
    "aarch64_generic_static_semantic_v1.elf"
)
EXAMPLES = ROOT / "examples/phase10d/static_fused_behavior"
TEXT_FILES = {
    "fused_graph.json",
    "fused_summary.md",
    "fused_graph.dot",
    "manifest.json",
}


def _fused(path: Path, artifact_id: str, fixture_id: str):
    artifact = ProgramArtifact(
        id=artifact_id,
        architecture=Architecture.ARM,
        artifact_type="elf",
        path=str(path),
        fixture_identifier=fixture_id,
        metadata={"owned": True, "synthetic": True, "fixture": True},
    )
    semantic = AngrAArch64StaticSemanticDecoder().decode(artifact)
    graph = project_static_semantic_inventory(semantic)
    structure = AngrAArch64StaticProgramStructureExtractor().extract(artifact)
    return fuse_static_semantic_and_program_structure(graph, structure)


@pytest.fixture(scope="module")
def flow():
    return _fused(
        FUSION_FIXTURE,
        "owned-synthetic-aarch64-static-fused-behavior-v1",
        "phase10d-aarch64-static-fused-behavior-v1",
    )


@pytest.fixture(scope="module")
def generic():
    return _fused(
        GENERIC_FIXTURE,
        "owned-synthetic-generic-aarch64-v1",
        "phase10d-aarch64-generic-static-semantic-v1",
    )


def _rendered(materialization) -> dict[str, str]:
    return {
        "fused_graph.json": render_static_fused_behavior_graph_json(
            materialization
        ),
        "fused_summary.md": render_static_fused_behavior_summary_markdown(
            materialization
        ),
        "fused_graph.dot": render_static_fused_behavior_graph_dot(
            materialization
        ),
    }


def test_fused_json_is_exact_canonical_materialization(flow) -> None:
    rendered = render_static_fused_behavior_graph_json(flow)

    assert json.loads(rendered) == flow.model_dump(mode="json")
    assert rendered.endswith("\n")
    assert not rendered.endswith("\n\n")


def test_flow_summary_has_exact_counts_and_table(flow) -> None:
    summary = render_static_fused_behavior_summary_markdown(flow)

    assert "- Function count: 1" in summary
    assert "- Basic-block count: 4" in summary
    assert "- Semantic-fact count: 4" in summary
    assert "- CFG successor count: 4" in summary
    assert "owned_fused_static_flow @ 0x400000" in summary
    assert "system_register_read @ 0x400000" in summary
    assert "memory_barrier @ 0x400008" in summary
    assert "tlb_invalidate @ 0x400010" in summary
    assert "instruction_barrier @ 0x400018" in summary
    assert "0x400008, 0x400010" in summary


def test_dot_contains_every_exact_fused_relation(flow) -> None:
    dot = render_static_fused_behavior_graph_dot(flow)
    edge_lines = [line for line in dot.splitlines() if " -> " in line]

    assert len(edge_lines) == len(flow.projection.relations) == 12
    assert sum('label="static CFG"' in line for line in edge_lines) == 4
    assert sum('label="contains block"' in line for line in edge_lines) == 4
    assert sum(
        'label="contains semantic fact"' in line for line in edge_lines
    ) == 4


def test_generic_eret_dot_has_direct_function_fact_edge(generic) -> None:
    projection = generic.projection
    node_names = {
        node.id: f"node_{index}"
        for index, node in enumerate(projection.nodes)
    }
    eret = next(
        node
        for node in projection.nodes
        if node.kind
        is StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT
        and node.instruction_address == "0x400034"
    )
    function = next(
        node
        for node in projection.nodes
        if node.kind is StaticFusedBehaviorNodeKind.FUNCTION
        and node.function_address == "0x400034"
    )
    relation = next(
        item
        for item in projection.relations
        if item.relation_kind
        is StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT
        and item.source_node_id == function.id
        and item.target_node_id == eret.id
    )
    dot = render_static_fused_behavior_graph_dot(generic)

    assert (
        f"{node_names[relation.source_node_id]} -> "
        f"{node_names[relation.target_node_id]}"
    ) in dot
    assert not any(
        node.kind is StaticFusedBehaviorNodeKind.BASIC_BLOCK
        and node.function_address == "0x400034"
        and node.basic_block_address == "0x400034"
        for node in projection.nodes
    )


def test_manifest_hashes_exact_written_text(flow, tmp_path: Path) -> None:
    result = export_static_fused_behavior_artifact_bundle(
        materialization=flow,
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


def test_manifest_has_no_machine_or_nondeterministic_metadata(
    flow, tmp_path: Path
) -> None:
    export_static_fused_behavior_artifact_bundle(
        materialization=flow,
        output_directory=tmp_path,
        include_svg=False,
    )
    content = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(tmp_path.iterdir())
    ).lower()

    assert str(ROOT).lower() not in content
    for forbidden in (
        "generated_at",
        "timestamp",
        "hostname",
        "username",
        "random_uuid",
        "python_version",
        "angr_version",
        "graphviz_version",
    ):
        assert forbidden not in content


def test_graphviz_absence_leaves_core_bundle_valid(
    flow,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        export_module,
        "render_dot_to_svg_if_available",
        lambda _source, _path: False,
    )

    result = export_static_fused_behavior_artifact_bundle(
        materialization=flow,
        output_directory=tmp_path,
    )

    assert set(result.files) == TEXT_FILES
    assert result.svg_files == ()
    assert not list(tmp_path.glob("*.svg"))


@pytest.mark.parametrize(
    ("directory", "fixture_name"),
    [("fused_flow", "flow"), ("generic_eret", "generic")],
)
def test_checked_in_bundle_matches_regeneration(
    directory: str,
    fixture_name: str,
    request: pytest.FixtureRequest,
    tmp_path: Path,
) -> None:
    materialization = request.getfixturevalue(fixture_name)
    result = export_static_fused_behavior_artifact_bundle(
        materialization=materialization,
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


@pytest.mark.parametrize("fixture_name", ["flow", "generic"])
def test_rendering_ten_times_is_deterministic(
    fixture_name: str,
    request: pytest.FixtureRequest,
) -> None:
    materialization = request.getfixturevalue(fixture_name)
    hashes = {
        filename: {
            hashlib.sha256(
                _rendered(materialization)[filename].encode("utf-8")
            ).hexdigest()
            for _ in range(10)
        }
        for filename in _rendered(materialization)
    }

    assert all(len(values) == 1 for values in hashes.values())


def test_rendering_does_not_mutate_materialization(flow) -> None:
    before = flow.model_dump_json()

    _rendered(flow)

    assert flow.model_dump_json() == before


def test_presentation_does_not_upgrade_static_meaning(flow) -> None:
    presentation = "\n".join(
        value
        for filename, value in _rendered(flow).items()
        if filename.endswith((".md", ".dot"))
    ).lower()
    for boundary in (
        "static fact != runtime execution.",
        "cfg_successor != runtime execution.",
        "cfg reachability != runtime reachability.",
        "cfg reachability != symbolic feasibility.",
        "cfg reachability != causality.",
        "fusion != verification.",
        "fusion != vulnerability.",
    ):
        presentation = presentation.replace(boundary, "")
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


def test_presentation_dependency_firewall() -> None:
    path = (
        ROOT
        / "src/chipchain/analysis/"
        "static_fused_behavior_artifact_export.py"
    )
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
