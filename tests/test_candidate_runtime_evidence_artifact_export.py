"""Presentation-only artifact tests for Phase 10D 2D4-B1."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import runpy

from chipchain.verification import (
    export_candidate_runtime_evidence_artifact_bundle,
    render_candidate_runtime_evidence_graph_dot,
    render_candidate_runtime_evidence_projection_json,
    render_candidate_runtime_evidence_summary_markdown,
)


ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "examples/phase10d/candidate_runtime_evidence/owned_diamond"
_RUNNER = runpy.run_path(
    str(ROOT / "scripts/export_candidate_runtime_evidence.py"),
    run_name="phase10d_candidate_runtime_evidence_artifact_runner",
)


def _materialization():
    return _RUNNER["build_owned_candidate_runtime_evidence_materialization"]()


def _tree(directory: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def test_renderers_are_deterministic_and_presentation_only() -> None:
    materialization = _materialization()
    for renderer in (
        render_candidate_runtime_evidence_projection_json,
        render_candidate_runtime_evidence_summary_markdown,
        render_candidate_runtime_evidence_graph_dot,
    ):
        assert renderer(materialization) == renderer(materialization)
    payload = json.loads(
        render_candidate_runtime_evidence_projection_json(materialization)
    )
    assert payload == materialization.projection.model_dump(mode="json")
    assert "source_requirement_materialization_snapshot" not in payload
    assert "source_runtime_trace_snapshots" not in payload


def test_summary_renders_exact_required_provenance_and_boundary() -> None:
    materialization = _materialization()
    summary = render_candidate_runtime_evidence_summary_markdown(materialization)
    for text in (
        "Endpoint instruction evidence does not establish runtime witness order.",
        "Runtime order evidence does not establish CFG path feasibility.",
        "Path acquisition gap records absence of B1 runtime-order evidence only.",
        "It is not a feasibility verdict.",
    ):
        assert text in summary
        assert text in render_candidate_runtime_evidence_graph_dot(materialization)
    assert all(code in summary for code in materialization.projection.diagnostic_codes)
    assert (
        "Runtime evidence only; requirement satisfaction has not been evaluated."
        in summary
    )
    for item in materialization.projection.instruction_evidence:
        assert item.id in summary
        assert item.source_runtime_trace_id in summary
        assert item.source_runtime_observation_id in summary
        assert item.observed_pc.value in summary
    for item in materialization.projection.order_evidence:
        assert item.source_static_order_witness_id in summary
        assert item.source_runtime_observation_id in summary
        assert item.target_runtime_observation_id in summary
    for item in materialization.projection.requirement_evidence_bindings:
        assert item.source_requirement_id in summary
        assert item.source_case_candidate_id in summary


def test_dot_contains_only_exact_source_and_binding_edges() -> None:
    materialization = _materialization()
    projection = materialization.projection
    dot = render_candidate_runtime_evidence_graph_dot(materialization)
    assert dot.count('[label="exact runtime observation"]') == (
        len(projection.instruction_evidence) + 2 * len(projection.order_evidence)
    )
    assert dot.count('[label="exact subject binding"]') == len(
        projection.requirement_evidence_bindings
    )
    assert "Runtime evidence only; requirement satisfaction has not been evaluated." in dot
    lowered = dot.lower()
    for forbidden in (
        "satisfies requirement",
        "verifies requirement",
        "proves path",
        "triggers vulnerability",
        "exploits vulnerability",
    ):
        assert forbidden not in lowered


def test_export_manifest_hashes_exact_text_files(tmp_path: Path) -> None:
    materialization = _materialization()
    result = export_candidate_runtime_evidence_artifact_bundle(
        materialization=materialization,
        output_directory=tmp_path,
        include_svg=False,
    )
    assert result.files == (
        "runtime_evidence.json",
        "runtime_evidence_summary.md",
        "runtime_evidence.dot",
        "manifest.json",
    )
    assert result.svg_files == ()
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["runtime_evidence_materialization_id"] == materialization.id
    assert manifest["runtime_evidence_projection_id"] == materialization.projection.id
    for filename, expected in manifest["files"].items():
        content = (tmp_path / filename).read_bytes()
        assert expected == {
            "byte_size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }


def test_ten_exports_have_one_textual_sha_per_filename(tmp_path: Path) -> None:
    materialization = _materialization()
    hashes: dict[str, set[str]] = {}
    for index in range(10):
        directory = tmp_path / str(index)
        export_candidate_runtime_evidence_artifact_bundle(
            materialization=materialization,
            output_directory=directory,
            include_svg=False,
        )
        for filename, content in _tree(directory).items():
            hashes.setdefault(filename, set()).add(
                hashlib.sha256(content).hexdigest()
            )
    assert set(hashes) == {
        "manifest.json",
        "runtime_evidence.dot",
        "runtime_evidence.json",
        "runtime_evidence_summary.md",
    }
    assert all(len(values) == 1 for values in hashes.values())


def test_committed_owned_golden_is_byte_exact(tmp_path: Path) -> None:
    export_candidate_runtime_evidence_artifact_bundle(
        materialization=_materialization(),
        output_directory=tmp_path,
        include_svg=False,
    )
    assert _tree(tmp_path) == _tree(GOLDEN)


def test_artifact_export_dependency_and_language_firewall() -> None:
    source = Path(
        "src/chipchain/verification/candidate_runtime_evidence_artifact_export.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "VerificationRecord",
        "VerificationStatus",
        "RuntimeEvidenceNormalizer",
        "AttackChain",
        "angr",
        "capstone",
        "provider",
        "qemu",
    ):
        assert forbidden not in source
