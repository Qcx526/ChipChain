"""Deterministic static cross-layer candidate presentation tests."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import runpy

import pytest

from chipchain.analysis import (
    export_static_cross_layer_candidate_artifact_bundle,
    render_static_cross_layer_candidate_graph_dot,
    render_static_cross_layer_candidate_projection_json,
    render_static_cross_layer_candidate_summary_markdown,
)


pytest.importorskip("angr")

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/export_static_cross_layer_candidates.py"
GOLDEN = (
    ROOT / "examples/phase10d/static_cross_layer_candidates/owned_diamond"
)


@pytest.fixture(scope="module")
def runner():
    return runpy.run_path(str(RUNNER))


@pytest.fixture(scope="module")
def owned(runner):
    return runner["build_owned_static_cross_layer_materialization"]()


@pytest.fixture(scope="module")
def public(runner):
    return runner["build_public_a77_static_cross_layer_materialization"]()


def test_owned_renderers_show_only_exact_reference_candidates(owned) -> None:
    projection = render_static_cross_layer_candidate_projection_json(owned)
    summary = render_static_cross_layer_candidate_summary_markdown(owned)
    dot = render_static_cross_layer_candidate_graph_dot(owned)
    assert owned.projection.id in projection
    assert "Binding count: 4" in summary
    assert "Unresolved reference count: 0" in summary
    assert dot.count('label="pattern-declared reference"') == 4
    assert dot.count("Firmware Static Candidate\\n") == 2
    assert dot.count("Owned Synthetic Hardware Reference\\n") == 2
    assert "documented CVE association" not in dot
    assert (
        "Static cross-layer reference candidate only; runtime execution, "
        "target applicability, and hardware effect remain unresolved."
        in summary
    )


def test_public_a77_zero_result_is_preserved_without_forcing_binding(public) -> None:
    candidates = public.source_candidate_materialization_snapshot.projection
    assert candidates.case_candidates == []
    assert public.projection.bindings == []
    assert public.projection.unresolved_references == []
    assert "Binding count: 0" in (
        render_static_cross_layer_candidate_summary_markdown(public)
    )


def test_owned_export_matches_checked_in_golden(owned, tmp_path: Path) -> None:
    result = export_static_cross_layer_candidate_artifact_bundle(
        materialization=owned,
        output_directory=tmp_path,
        include_svg=False,
    )
    assert result.files == (
        "cross_layer_projection.json",
        "cross_layer_summary.md",
        "cross_layer_graph.dot",
        "manifest.json",
    )
    assert result.svg_files == ()
    for filename in result.files:
        assert (tmp_path / filename).read_bytes() == (
            GOLDEN / filename
        ).read_bytes()


def test_owned_export_is_byte_deterministic_across_ten_runs(
    owned, tmp_path: Path
) -> None:
    hashes: dict[str, set[str]] = {}
    for index in range(10):
        output = tmp_path / str(index)
        result = export_static_cross_layer_candidate_artifact_bundle(
            materialization=owned,
            output_directory=output,
            include_svg=False,
        )
        for filename in result.files:
            hashes.setdefault(filename, set()).add(
                hashlib.sha256((output / filename).read_bytes()).hexdigest()
            )
    assert all(len(values) == 1 for values in hashes.values())


def test_presentation_is_pure_and_runner_is_offline() -> None:
    presentation = ast.parse(
        (
            ROOT
            / "src/chipchain/analysis/"
            "static_cross_layer_candidate_artifact_export.py"
        ).read_text(encoding="utf-8")
    )
    presentation_imports = {
        node.module or ""
        for node in ast.walk(presentation)
        if isinstance(node, ast.ImportFrom)
    }
    assert not any(
        term in module
        for module in presentation_imports
        for term in (
            "decoder",
            "extractor",
            "candidate_matching",
            "runtime",
            "provider",
        )
    )
    runner_text = RUNNER.read_text(encoding="utf-8").lower()
    for term in ("requests", "http://", "https://", "qemu", "provider"):
        assert term not in runner_text


def test_new_presentation_contains_no_positive_outcome_claims(owned) -> None:
    rendered = "\n".join(
        (
            render_static_cross_layer_candidate_summary_markdown(owned),
            render_static_cross_layer_candidate_graph_dot(owned),
        )
    ).lower()
    for statement in (
        "vulnerability detected",
        "triggered erratum",
        "cve reproduced",
        "affected target",
        "deadlock observed",
        "exploit possible",
        "verified attack chain",
    ):
        assert statement not in rendered
