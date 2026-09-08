"""Golden and language-boundary tests for the B2-B artifact bundle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import runpy

import pytest

from chipchain.verification import (
    CandidateStateObservationFamily,
    export_candidate_state_requirement_binding_artifact_bundle,
    render_candidate_state_requirement_binding_graph_dot,
    render_candidate_state_requirement_binding_projection_json,
    render_candidate_state_requirement_binding_summary_markdown,
)


ROOT = Path(__file__).resolve().parents[1]
GOLDEN = (
    ROOT
    / "examples/phase10d/candidate_state_requirement_bindings/owned"
)
FIXTURE = (
    ROOT
    / "tests/fixtures/phase10d/candidate_state_requirement_binding_v1"
)
RUNNER = runpy.run_path(
    str(ROOT / "scripts/export_candidate_state_requirement_bindings.py"),
    run_name="phase10d_b2b_export_test_runner",
)


@pytest.fixture(scope="module")
def result():
    return RUNNER["build_owned_state_requirement_binding_materialization"]()


def test_projection_json_and_summary_are_complete_and_non_evaluative(result) -> None:
    projection_text = render_candidate_state_requirement_binding_projection_json(
        result
    )
    assert json.loads(projection_text) == result.projection.model_dump(mode="json")
    summary = render_candidate_state_requirement_binding_summary_markdown(result)
    assert "Source relevance only; requirement satisfaction has not been evaluated." in summary
    assert "Program-location state association does not establish runtime execution or a memory access by that instruction." in summary
    assert "Value equality is not evaluated by this binding layer." in summary
    observations = {
        item.id: item
        for source in result.source_state_observation_materialization_snapshots
        for item in [
            *source.effective_memory_type_observations,
            *source.execution_context_observations,
        ]
    }
    for binding in result.projection.observation_requirement_bindings:
        observation = observations[binding.source_state_observation_id]
        for value in (
            binding.id,
            binding.source_requirement_id,
            binding.source_case_candidate_id,
            binding.source_state_materialization_id,
            binding.source_state_manifest_id,
            binding.source_state_observation_id,
            binding.source_requirement_kind.value,
            binding.source_observation_family.value,
            observation.instruction_address.value,
            *binding.matched_subject_position_candidate_ids,
            *binding.matched_subject_fused_fact_node_ids,
        ):
            assert value in summary
        if binding.source_observation_family is (
            CandidateStateObservationFamily.EFFECTIVE_MEMORY_TYPE
        ):
            assert observation.access_address.value in summary
            assert observation.observed_effective_memory_type_id in summary
        else:
            assert all(
                value in summary
                for value in observation.observed_execution_context_ids
            )
    for forbidden in (
        "required value matched",
        "requirement passed",
        "supports verified",
        "confirms",
        "proves",
        "executed access",
    ):
        assert forbidden not in summary.lower()


def test_dot_has_exactly_one_pure_edge_per_binding(result) -> None:
    dot = render_candidate_state_requirement_binding_graph_dot(result)
    assert dot.count(" -> ") == len(
        result.projection.observation_requirement_bindings
    )
    assert dot.count('label="exact program-location source relevance"') == len(
        result.projection.observation_requirement_bindings
    )
    assert "Source relevance only; requirement satisfaction has not been evaluated." in dot
    assert "Program-location state association does not establish runtime execution or a memory access by that instruction." in dot
    assert "Value equality is not evaluated by this binding layer." in dot
    for forbidden in (
        "satisfies",
        "supports verified",
        "confirms",
        "proves",
        "executed access",
    ):
        assert forbidden not in dot.lower()


def test_export_matches_golden_and_hash_manifest(result, tmp_path) -> None:
    output = tmp_path / "bundle"
    exported = export_candidate_state_requirement_binding_artifact_bundle(
        materialization=result, output_directory=output
    )
    expected_files = (
        "state_requirement_bindings.json",
        "state_requirement_bindings_summary.md",
        "state_requirement_bindings.dot",
        "manifest.json",
    )
    assert exported.files == expected_files
    assert sorted(item.name for item in output.iterdir()) == sorted(expected_files)
    for filename in expected_files:
        assert (output / filename).read_bytes() == (GOLDEN / filename).read_bytes()
    manifest = json.loads((output / "manifest.json").read_bytes())
    for filename in expected_files[:-1]:
        content = (output / filename).read_bytes()
        assert manifest["files"][filename] == {
            "byte_size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    assert manifest["binding_materialization_id"] == result.id
    assert manifest["binding_projection_id"] == result.projection.id


def test_ten_renders_have_one_sha_per_artifact(result) -> None:
    renderers = {
        "json": render_candidate_state_requirement_binding_projection_json,
        "summary": render_candidate_state_requirement_binding_summary_markdown,
        "dot": render_candidate_state_requirement_binding_graph_dot,
    }
    for renderer in renderers.values():
        hashes = {
            hashlib.sha256(renderer(result).encode("utf-8")).hexdigest()
            for _ in range(10)
        }
        assert len(hashes) == 1


def test_ten_complete_exports_have_one_sha_per_file(result, tmp_path) -> None:
    hashes: dict[str, set[str]] = {}
    for index in range(10):
        output = tmp_path / str(index)
        exported = export_candidate_state_requirement_binding_artifact_bundle(
            materialization=result, output_directory=output
        )
        for filename in exported.files:
            hashes.setdefault(filename, set()).add(
                hashlib.sha256((output / filename).read_bytes()).hexdigest()
            )
    assert set(hashes) == {
        "state_requirement_bindings.json",
        "state_requirement_bindings_summary.md",
        "state_requirement_bindings.dot",
        "manifest.json",
    }
    assert all(len(values) == 1 for values in hashes.values())


def test_fixture_sha_and_runner_have_no_test_imports() -> None:
    expected = (FIXTURE / "SHA256SUMS").read_text(encoding="utf-8").strip()
    digest, filename = expected.split()
    assert filename == "owned_state_source.json"
    assert hashlib.sha256((FIXTURE / filename).read_bytes()).hexdigest() == digest
    runner_source = (
        ROOT / "scripts/export_candidate_state_requirement_bindings.py"
    ).read_text(encoding="utf-8")
    assert "from tests" not in runner_source
    assert "import tests" not in runner_source
