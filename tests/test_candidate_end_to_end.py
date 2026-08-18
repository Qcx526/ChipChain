"""Phase 4B + Phase 5 + Phase 6 owned ARM end-to-end tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from chipchain.analysis import (
    AngrAnalyzer,
    MemoryMap,
    ProgramArtifact,
    ingest_analysis_result,
)
from chipchain.candidate import CrossGraphCandidateSearcher
from chipchain.graph import NetworkXGraphRepository
from chipchain.knowledge import (
    NetworkXKnowledgeGraphRepository,
    VulnerabilityKnowledgeBuilder,
)
from chipchain.models import Architecture, Layer, VulnerabilitySample

pytest.importorskip("angr")
pytestmark = pytest.mark.angr

ROOT = Path(__file__).resolve().parents[1]
MMIO_DIRECTORY = ROOT / "tests" / "fixtures" / "angr" / "arm_mmio"


def build_real_fixture_repositories() -> tuple[
    NetworkXGraphRepository,
    NetworkXKnowledgeGraphRepository,
]:
    """Build both independent repositories from existing owned fixtures."""

    memory_map = MemoryMap.model_validate_json(
        (MMIO_DIRECTORY / "memory_map.json").read_text(encoding="utf-8")
    )
    artifact = ProgramArtifact(
        id="synthetic-arm-mmio",
        architecture=Architecture.ARM,
        artifact_type="elf",
        program_layer=Layer.DRIVER,
        path=str(MMIO_DIRECTORY / "arm_mmio.elf"),
        fixture_identifier="synthetic-arm-mmio-elf",
        metadata={"fixture": True, "synthetic": True, "owned": True},
    )
    result = AngrAnalyzer(memory_map=memory_map).analyze(artifact)
    behavior = NetworkXGraphRepository(metadata={"fixture": True})
    ingest_analysis_result(result, behavior)

    sample_data = json.loads(
        (
            ROOT
            / "tests"
            / "fixtures"
            / "knowledge"
            / "synthetic_arm_vulnerability.json"
        ).read_text(encoding="utf-8")
    )
    knowledge = NetworkXKnowledgeGraphRepository.from_bundle(
        VulnerabilityKnowledgeBuilder().build(
            VulnerabilitySample.model_validate(sample_data)
        )
    )
    return behavior, knowledge


def test_actual_arm_mmio_analysis_produces_unverified_candidates() -> None:
    """Real machine-code observations correlate to KG context through exact keys."""

    behavior, knowledge = build_real_fixture_repositories()
    candidates = CrossGraphCandidateSearcher().search(
        behavior,
        knowledge,
        architecture=Architecture.ARM,
        start_node_id="synthetic-arm-mmio:function:00010030",
        max_hops=2,
    )

    assert len(candidates) == 3
    assert all(item.behavior_path.hop_count == 2 for item in candidates)
    assert all(len(item.entity_link.match_keys) == 2 for item in candidates)
    assert all(len(item.trigger_node_ids) == 1 for item in candidates)
    assert all(len(item.precondition_node_ids) == 1 for item in candidates)
    assert all(len(item.impact_node_ids) == 1 for item in candidates)
    assert all(
        item.metadata["status"] == "unverified_correlation"
        for item in candidates
    )


def test_candidate_demo_prints_explicit_non_verification_boundary() -> None:
    """The executable demo reports a correlation, never a confirmed attack."""

    completed = subprocess.run(
        [sys.executable, "examples/arm_candidate_search_demo.py"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "ChipChain Phase 6 candidate correlation demo" in completed.stdout
    assert "main\n -> CALLS\ndriver_like_function" in completed.stdout
    assert " -> MMIO_WRITE\nFIXTURE_MMIO_REGISTER" in completed.stdout
    assert "arch:arm:address:0x40000000" in completed.stdout
    assert "Knowledge Candidate: vulnerability:FIXTURE-ARM-KG-001" in completed.stdout
    assert "Trigger Count: 1" in completed.stdout
    assert "Precondition Count: 1" in completed.stdout
    assert "Impact Count: 1" in completed.stdout
    assert "Candidate Status: unverified correlation" in completed.stdout
    assert "This is not a verified attack chain." in completed.stdout
