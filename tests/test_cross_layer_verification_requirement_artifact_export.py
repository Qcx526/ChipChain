"""Deterministic presentation tests for 2D4-A requirement artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path
import runpy

import pytest

from chipchain.verification import (
    export_cross_layer_verification_requirement_artifact_bundle,
    project_cross_layer_verification_requirements,
    render_cross_layer_verification_requirement_graph_dot,
    render_cross_layer_verification_requirement_projection_json,
    render_cross_layer_verification_requirement_summary_markdown,
)

pytest.importorskip("angr")

ROOT = Path(__file__).resolve().parents[1]
_RUNNER = runpy.run_path(
    str(ROOT / "scripts/export_static_cross_layer_candidates.py"),
    run_name="phase10d_requirement_artifact_source_runner",
)


@pytest.fixture(scope="module")
def materialization():
    return project_cross_layer_verification_requirements(
        _RUNNER["build_owned_static_cross_layer_materialization"]()
    )


def test_renderers_are_pure_and_use_requirement_language(materialization) -> None:
    before = materialization.model_dump_json()
    rendered = (
        render_cross_layer_verification_requirement_projection_json(materialization),
        render_cross_layer_verification_requirement_summary_markdown(materialization),
        render_cross_layer_verification_requirement_graph_dot(materialization),
    )
    assert materialization.model_dump_json() == before
    assert "Requirements only; no evidence has been evaluated." in rendered[1]
    assert "requires objective evidence" in rendered[2]
    for forbidden in ("verified by", "satisfied by", "proves", "triggered", "causes", "attack chain"):
        assert forbidden not in rendered[2].lower()


def test_bundle_is_byte_deterministic(tmp_path, materialization) -> None:
    hashes = []
    for index in range(10):
        directory = tmp_path / str(index)
        result = export_cross_layer_verification_requirement_artifact_bundle(
            materialization=materialization, output_directory=directory, include_svg=False
        )
        assert result.files == (
            "verification_requirements.json", "verification_requirements_summary.md",
            "verification_requirements.dot", "manifest.json",
        )
        hashes.append(tuple(hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in result.files))
    assert len(set(hashes)) == 1


def test_checked_in_owned_bundle_matches_exactly(tmp_path, materialization) -> None:
    export_cross_layer_verification_requirement_artifact_bundle(
        materialization=materialization, output_directory=tmp_path, include_svg=False
    )
    golden = ROOT / "examples/phase10d/cross_layer_verification_requirements/owned_diamond"
    for name in ("verification_requirements.json", "verification_requirements_summary.md", "verification_requirements.dot", "manifest.json"):
        assert (tmp_path / name).read_bytes() == (golden / name).read_bytes()


def test_public_zero_projection_renders_zero_counts() -> None:
    value = project_cross_layer_verification_requirements(
        _RUNNER["build_public_a77_static_cross_layer_materialization"]()
    )
    summary = render_cross_layer_verification_requirement_summary_markdown(value)
    assert "Candidate requirement count: 0" in summary
    assert "Binding requirement count: 0" in summary
