"""Tests for deterministic observable behavior extraction by DemoAnalyzer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from chipchain.analysis import (
    DemoAnalyzer,
    InvalidAnalysisInputError,
    ProgramAnalysisResult,
    ProgramArtifact,
    UnsupportedArtifactError,
)
from chipchain.models import EvidenceType, NodeKind, RelationType


def test_analysis_is_deterministic_independent_of_spec_order(
    demo_program_artifact: ProgramArtifact,
    demo_program_spec_data: dict[str, Any],
    tmp_path: Path,
) -> None:
    """Input list ordering cannot change result ordering or serialized semantics."""

    reordered_path = tmp_path / "reordered-spec.json"
    reordered_path.write_text(json.dumps(demo_program_spec_data), encoding="utf-8")
    reordered_artifact = ProgramArtifact(
        **{
            **demo_program_artifact.model_dump(mode="python"),
            "path": str(reordered_path),
        }
    )
    original = DemoAnalyzer().analyze(reordered_artifact)
    demo_program_spec_data["functions"].reverse()
    demo_program_spec_data["calls"].reverse()
    demo_program_spec_data["ioctls"].reverse()
    demo_program_spec_data["mmio_accesses"].reverse()
    reordered_path.write_text(json.dumps(demo_program_spec_data), encoding="utf-8")

    shuffled = DemoAnalyzer().analyze(reordered_artifact)

    assert shuffled == original
    assert [node.id for node in shuffled.nodes] == sorted(
        node.id for node in shuffled.nodes
    )
    assert [edge.id for edge in shuffled.edges] == sorted(
        edge.id for edge in shuffled.edges
    )
    assert [item.id for item in shuffled.evidence] == sorted(
        item.id for item in shuffled.evidence
    )


def test_function_driver_interface_and_register_nodes_are_generated(
    demo_analysis_result: ProgramAnalysisResult,
) -> None:
    """The adapter discovers reusable domain nodes rather than returning spec objects."""

    node_by_id = {node.id: node for node in demo_analysis_result.nodes}

    assert node_by_id["fixture_parse_command"].kind is NodeKind.FUNCTION
    assert node_by_id["fixture_driver_ioctl"].kind is NodeKind.DRIVER_FUNCTION
    assert node_by_id["fixture_ioctl"].kind is NodeKind.INTERFACE
    assert node_by_id["fixture_debug_ctrl"].kind is NodeKind.REGISTER
    assert node_by_id["fixture_debug_ctrl"].address == "0x50000000"


def test_sensitive_marker_is_an_observation_not_a_vulnerability(
    demo_analysis_result: ProgramAnalysisResult,
) -> None:
    """MMIO functions are marked for review without vulnerability claims."""

    node_by_id = {node.id: node for node in demo_analysis_result.nodes}
    driver_metadata = node_by_id["fixture_driver_ioctl"].metadata

    assert driver_metadata["sensitive"] is True
    assert driver_metadata["sensitive_reasons"] == ["mmio_write"]
    assert all("vulnerable" not in node.metadata for node in demo_analysis_result.nodes)
    assert not {NodeKind.WEAKNESS, NodeKind.IMPACT}.intersection(
        node.kind for node in demo_analysis_result.nodes
    )


def test_call_ioctl_and_mmio_relations_are_generated(
    demo_analysis_result: ProgramAnalysisResult,
) -> None:
    """All required Phase 3 observable relation types should be present."""

    relations = {edge.relation for edge in demo_analysis_result.edges}

    assert {
        RelationType.CALLS,
        RelationType.ISSUES,
        RelationType.INVOKES,
        RelationType.MMIO_WRITE,
    }.issubset(relations)


def test_all_behavior_edges_have_static_fixture_evidence(
    demo_analysis_result: ProgramAnalysisResult,
) -> None:
    """Behavior facts and their fixture evidence remain separate and linked."""

    evidence_by_id = {item.id: item for item in demo_analysis_result.evidence}

    assert len(evidence_by_id) == 4
    for edge in demo_analysis_result.edges:
        assert edge.evidence_ids
        for evidence_id in edge.evidence_ids:
            item = evidence_by_id[evidence_id]
            assert item.type is EvidenceType.STATIC_ANALYSIS
            assert item.source == "demo_analyzer"
            assert item.verified is True
            assert item.confidence == 1.0
            assert item.metadata["fixture"] is True


def test_callsite_and_mmio_evidence_preserve_locations(
    demo_analysis_result: ProgramAnalysisResult,
) -> None:
    """CALL XRef and MMIO observations retain their distinct instruction locations."""

    evidence_by_id = {item.id: item for item in demo_analysis_result.evidence}
    call_evidence = evidence_by_id["fixture-call-parse-send-evidence"]
    mmio_evidence = evidence_by_id["fixture-mmio-access-evidence"]

    assert call_evidence.address == "0x00401020"
    assert call_evidence.instruction == "BL fixture_send_ioctl"
    assert mmio_evidence.address == "0x00402030"
    assert mmio_evidence.metadata["mmio_address"] == "0x50000000"
    assert mmio_evidence.instruction == "STR fixture_value, [fixture_mmio_base]"


def test_unsupported_artifact_type_uses_stable_error(
    demo_program_artifact: ProgramArtifact,
) -> None:
    """DemoAnalyzer must not pretend to analyze an ELF or binary."""

    artifact = ProgramArtifact(
        id=demo_program_artifact.id,
        architecture=demo_program_artifact.architecture,
        artifact_type="elf",
        path=demo_program_artifact.path,
    )

    with pytest.raises(UnsupportedArtifactError):
        DemoAnalyzer().analyze(artifact)


def test_malformed_file_is_wrapped_as_invalid_analysis_input(tmp_path: Path) -> None:
    """JSON parser failures should not leak through the public analyzer API."""

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not-json", encoding="utf-8")
    artifact = ProgramArtifact(
        id="fixture-arm-program",
        architecture="arm",
        artifact_type="fixture",
        path=str(malformed),
    )

    with pytest.raises(InvalidAnalysisInputError) as exc_info:
        DemoAnalyzer().analyze(artifact)

    assert isinstance(exc_info.value.__cause__, json.JSONDecodeError)


def test_artifact_and_spec_architecture_mismatch_is_rejected(
    demo_program_spec_path: Path,
) -> None:
    """Artifact architecture remains authoritative at the adapter boundary."""

    artifact = ProgramArtifact(
        id="fixture-arm-program",
        architecture="risc_v",
        artifact_type="fixture",
        path=str(demo_program_spec_path),
    )

    with pytest.raises(InvalidAnalysisInputError, match="architecture"):
        DemoAnalyzer().analyze(artifact)
