"""Golden presentation tests for static trigger candidate artifacts."""

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
    StaticTriggerPattern,
    StaticTriggerPatternCatalog,
    export_static_trigger_candidate_artifact_bundle,
    fuse_static_semantic_and_program_structure,
    project_static_semantic_inventory,
    project_static_trigger_candidates,
    render_static_trigger_candidate_projection_json,
    render_static_trigger_candidate_summary_markdown,
    render_static_trigger_candidate_witness_dot,
)
from chipchain.models import Architecture


pytest.importorskip("angr")
pytestmark = pytest.mark.angr

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
EXAMPLE = (
    ROOT
    / "examples/phase10d/static_trigger_candidates/owned_diamond"
)
TEXT_FILES = {
    "candidate_projection.json",
    "candidate_summary.md",
    "candidate_witness.dot",
    "manifest.json",
}


@pytest.fixture(scope="module")
def owned_candidates():
    artifact = ProgramArtifact(
        id="owned-synthetic-aarch64-static-fused-behavior-v1",
        architecture=Architecture.ARM,
        artifact_type="elf",
        path=str(FUSED_ELF),
        fixture_identifier="phase10d-aarch64-static-fused-behavior-v1",
        metadata={"owned": True, "synthetic": True, "fixture": True},
    )
    semantic = AngrAArch64StaticSemanticDecoder().decode(artifact)
    semantic_graph = project_static_semantic_inventory(semantic)
    structure = AngrAArch64StaticProgramStructureExtractor().extract(artifact)
    fused = fuse_static_semantic_and_program_structure(
        semantic_graph, structure
    )
    pattern = StaticTriggerPattern.model_validate_json(
        PATTERN_JSON.read_bytes()
    )
    catalog = StaticTriggerPatternCatalog.create(patterns=[pattern])
    return project_static_trigger_candidates(fused, catalog)


def _rendered(owned_candidates) -> dict[str, str]:
    return {
        "candidate_projection.json": (
            render_static_trigger_candidate_projection_json(owned_candidates)
        ),
        "candidate_summary.md": (
            render_static_trigger_candidate_summary_markdown(owned_candidates)
        ),
        "candidate_witness.dot": (
            render_static_trigger_candidate_witness_dot(owned_candidates)
        ),
    }


def test_projection_json_is_exact_canonical_projection(owned_candidates) -> None:
    rendered = render_static_trigger_candidate_projection_json(
        owned_candidates
    )
    assert json.loads(rendered) == owned_candidates.projection.model_dump(
        mode="json"
    )
    assert rendered.endswith("\n")
    assert not rendered.endswith("\n\n")


def test_summary_has_exact_sources_positions_witnesses_and_boundaries(
    owned_candidates,
) -> None:
    summary = render_static_trigger_candidate_summary_markdown(
        owned_candidates
    )
    assert "owned_synthetic_diamond_static_pattern" in summary
    assert "owned-case-a" in summary
    assert "owned-case-b" in summary
    for address in ("0x400000", "0x400008", "0x400010", "0x400018"):
        assert address in summary
    assert "directed_function_cfg_path" in summary
    assert "runtime_execution_required" in summary
    assert "symbolic_path_feasibility_remains_unresolved" in summary
    assert "static structural pattern candidate only" in summary
    assert "Pattern Candidate != Triggerability." in summary
    assert "Pattern Hardware Reference != Candidate Hardware Binding." in summary


def test_dot_shows_only_static_candidate_witnesses(owned_candidates) -> None:
    dot = render_static_trigger_candidate_witness_dot(owned_candidates)
    assert dot.count('label="static CFG witness"') == 4
    assert "Static candidate only" in dot
    forbidden = ("executes", "causes", "triggers", "exploits", "attack chain")
    assert not any(value in dot.lower() for value in forbidden)


def test_checked_in_owned_bundle_is_byte_exact(owned_candidates) -> None:
    rendered = _rendered(owned_candidates)
    manifest = json.loads((EXAMPLE / "manifest.json").read_text())
    assert set(path.name for path in EXAMPLE.iterdir()) == TEXT_FILES
    for filename, text in rendered.items():
        assert (EXAMPLE / filename).read_bytes() == text.encode("utf-8")
        assert manifest["files"][filename] == {
            "byte_size": len(text.encode("utf-8")),
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        }
    assert manifest["candidate_projection_id"] == (
        owned_candidates.projection.id
    )
    assert manifest["candidate_materialization_id"] == owned_candidates.id


def test_bundle_export_is_byte_deterministic_across_ten_runs(
    owned_candidates,
    tmp_path: Path,
) -> None:
    hashes: dict[str, set[str]] = {filename: set() for filename in TEXT_FILES}
    for index in range(10):
        output = tmp_path / str(index)
        result = export_static_trigger_candidate_artifact_bundle(
            materialization=owned_candidates,
            output_directory=output,
            include_svg=False,
        )
        assert set(result.files) == TEXT_FILES
        assert result.svg_files == ()
        for filename in TEXT_FILES:
            hashes[filename].add(
                hashlib.sha256((output / filename).read_bytes()).hexdigest()
            )
    assert all(len(values) == 1 for values in hashes.values())


def test_manifest_is_path_time_and_host_neutral(owned_candidates, tmp_path) -> None:
    output = tmp_path / "bundle"
    export_static_trigger_candidate_artifact_bundle(
        materialization=owned_candidates,
        output_directory=output,
        include_svg=False,
    )
    manifest = (output / "manifest.json").read_text()
    lowered = manifest.lower()
    assert str(tmp_path) not in manifest
    assert not any(
        value in lowered
        for value in ("timestamp", "hostname", "username", "uuid", "cwd")
    )


def test_presentation_module_contains_no_analysis_or_matching_algorithm() -> None:
    path = (
        ROOT
        / "src/chipchain/analysis/"
        "static_trigger_candidate_artifact_export.py"
    )
    tree = ast.parse(path.read_text())
    names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "project_static_trigger_candidates" not in names
    assert "_predicate_matches" not in names
    assert "canonical_cfg_path" not in names


def test_runner_only_orchestrates_and_has_no_network_or_runtime_imports() -> None:
    path = ROOT / "scripts/export_static_trigger_candidates.py"
    tree = ast.parse(path.read_text())
    modules = {
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not any(
        fragment in module
        for module in modules
        for fragment in ("runtime", "qemu", "provider", "requests")
    )
