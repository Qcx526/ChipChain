"""B2-A deterministic source-only bundle regression, without external tools."""

import hashlib
import json
from pathlib import Path
import runpy

from chipchain.verification.candidate_state_observation_models import CandidateStateObservationMaterialization
from chipchain.verification.candidate_state_observation_artifact_export import (
    export_candidate_state_observations,
    render_candidate_state_observations_dot,
    render_candidate_state_observations_summary,
)

ROOT = Path(__file__).resolve().parents[1]
RUNNER = runpy.run_path(str(ROOT / "scripts/export_candidate_state_observations.py"))
GOLDEN = ROOT / "examples/phase10d/candidate_state_observations/owned_diamond"


def _tree(path):
    return {p.name: p.read_bytes() for p in path.iterdir() if p.is_file()}


def test_ten_regenerations_and_input_order_equal_golden(tmp_path):
    outputs, manifest_ids, materialization_ids = [], set(), set()
    for index in range(10):
        source = RUNNER["build_owned_candidate_state_observations"]()
        if index % 2:
            values = source.model_dump(mode="json", exclude={"contract", "id"})
            values["effective_memory_type_observations"].reverse()
            values["execution_context_observations"][0]["observed_execution_context_ids"].reverse()
            source = CandidateStateObservationMaterialization.create(**values)
        destination = tmp_path / str(index)
        filenames = export_candidate_state_observations(materialization=source, output_directory=destination)
        assert set(filenames) == {"state_observations.json", "state_observations_summary.md", "state_observations.dot", "manifest.json"}
        outputs.append(_tree(destination))
        manifest_ids.add(source.source_manifest_snapshot.id)
        materialization_ids.add(source.id)
    assert len(manifest_ids) == len(materialization_ids) == 1
    assert all(output == _tree(GOLDEN) for output in outputs)
    for filename in outputs[0]:
        assert len({hashlib.sha256(output[filename]).hexdigest() for output in outputs}) == 1


def test_bundle_manifest_and_source_roundtrip():
    files = _tree(GOLDEN)
    manifest = json.loads(files["manifest.json"])
    source = CandidateStateObservationMaterialization.model_validate_json(files["state_observations.json"])
    assert manifest["source_manifest_id"] == source.source_manifest_snapshot.id
    assert manifest["source_materialization_id"] == source.id
    for name, entry in manifest["files"].items():
        assert entry == {"sha256": hashlib.sha256(files[name]).hexdigest(), "byte_size": len(files[name])}
    assert "status" not in manifest


def test_visible_boundaries_and_dot_has_only_source_edges():
    source = RUNNER["build_owned_candidate_state_observations"]()
    dot = render_candidate_state_observations_dot(source)
    summary = render_candidate_state_observations_summary(source)
    boundary = "Typed state observations only; no verification requirement has been evaluated."
    assert boundary in dot and boundary in summary
    edges = [line.strip() for line in dot.splitlines() if " -> " in line]
    assert len(edges) == 3
    assert all(line.startswith("source -> observation_") for line in edges)
    for forbidden_node in ("Requirement\\n", "Candidate\\n", "CVE\\n", "Vulnerability\\n", "AttackChain\\n"):
        assert forbidden_node not in dot
    assert "State-source instruction addresses do not assert runtime execution." in summary
    assert "does not establish that the instruction performed that memory access" in summary
    assert "producer-profile-declared deterministic normalization basis" in summary
    assert "Program-location association does not establish runtime execution or a memory access by that instruction." in dot
    assert "Declared source artifact hash is not independent raw-file verification." in summary
    for record in [*source.effective_memory_type_observations, *source.execution_context_observations]:
        assert record.id in dot and record.id in summary
        assert record.source_record_locator in summary
