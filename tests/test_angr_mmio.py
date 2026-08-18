"""Phase 4B integration tests for real ARM memory observations."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from chipchain.analysis import (
    AngrAnalyzer,
    InvalidAnalysisInputError,
    MemoryMap,
    ProgramAnalysisResult,
    ProgramArtifact,
    ingest_analysis_result,
)
from chipchain.graph import NetworkXGraphRepository
from chipchain.knowledge import (
    KnowledgeNodeKind,
    VulnerabilityKnowledgeBuilder,
    hardware_resource_match_keys,
)
from chipchain.models import Architecture, EvidenceType, Layer, NodeKind, RelationType
from chipchain.models import VulnerabilitySample

angr = pytest.importorskip("angr")

pytestmark = pytest.mark.angr

FIXTURE_DIRECTORY = Path(__file__).parent / "fixtures" / "angr" / "arm_mmio"
FIXTURE_PATH = FIXTURE_DIRECTORY / "arm_mmio.elf"
MEMORY_MAP_PATH = FIXTURE_DIRECTORY / "memory_map.json"
ARTIFACT_ID = "synthetic-arm-mmio"
HARDWARE_NODE_ID = (
    f"{ARTIFACT_ID}:memory-map:synthetic-arm-mmio-map:"
    "region:fixture-mmio-register"
)


@pytest.fixture
def mmio_memory_map() -> MemoryMap:
    """Load the explicit synthetic ARM device map."""

    return MemoryMap.model_validate_json(MEMORY_MAP_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def driver_artifact() -> ProgramArtifact:
    """Return the owned ARM ELF labeled as driver program code."""

    return ProgramArtifact(
        id=ARTIFACT_ID,
        architecture=Architecture.ARM,
        artifact_type="elf",
        program_layer=Layer.DRIVER,
        path=str(FIXTURE_PATH),
        fixture_identifier="synthetic-arm-mmio-elf",
        metadata={"fixture": True, "synthetic": True, "owned": True},
    )


@pytest.fixture
def mmio_result(
    driver_artifact: ProgramArtifact,
    mmio_memory_map: MemoryMap,
) -> ProgramAnalysisResult:
    """Analyze the real ARM memory-access fixture."""

    return AngrAnalyzer(memory_map=mmio_memory_map).analyze(driver_artifact)


def test_mmio_fixture_hash_and_ground_truth_are_auditable() -> None:
    """The owned ELF must retain its recorded bytes and positive/negative truth."""

    digest, filename = (FIXTURE_DIRECTORY / "SHA256SUMS").read_text(
        encoding="ascii"
    ).split()
    truth = json.loads(
        (FIXTURE_DIRECTORY / "ground_truth.json").read_text(encoding="utf-8")
    )

    assert filename == FIXTURE_PATH.name
    assert hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest() == digest
    assert truth["fixture_type"] == "synthetic"
    assert truth["owned"] is True
    assert truth["vulnerability_sample"] is False
    assert len(truth["expected_mmio_accesses"]) == 3
    assert len(truth["non_mmio_accesses"]) == 2
    assert len(truth["unresolved_memory_accesses"]) == 2


def test_actual_mmio_elf_loads_as_arm() -> None:
    """The positive fixture is real A32 machine code in a valid ARM ELF."""

    project = angr.Project(str(FIXTURE_PATH), auto_load_libs=False)

    assert project.arch.name == "ARMEL"
    assert project.arch.bits == 32
    assert project.entry == 0x10030
    assert project.loader.main_object.min_addr == 0x10000
    assert project.loader.main_object.max_addr == 0x1003B


def test_driver_layer_calls_and_mmio_relations_coexist(
    mmio_result: ProgramAnalysisResult,
) -> None:
    """Phase 4B adds cross-layer facts without losing Phase 4 CALLS."""

    function_nodes = [node for node in mmio_result.nodes if node.kind is NodeKind.FUNCTION]
    relations = [edge.relation for edge in mmio_result.edges]

    assert {node.name for node in function_nodes} == {"main", "driver_like_function"}
    assert all(node.layer is Layer.DRIVER for node in function_nodes)
    assert relations.count(RelationType.CALLS) == 1
    assert relations.count(RelationType.MMIO_WRITE) == 2
    assert relations.count(RelationType.MMIO_READ) == 1
    assert mmio_result.metadata["resolved_call_count"] == 1
    assert mmio_result.metadata["resolved_mmio_accesses"] == 3


def test_resolved_mmio_accesses_match_ground_truth(
    mmio_result: ProgramAnalysisResult,
) -> None:
    """Only concrete VEX addresses inside the explicit map become MMIO facts."""

    evidence_by_id = {item.id: item for item in mmio_result.evidence}
    observed = set()
    for edge in mmio_result.edges:
        if edge.relation not in {RelationType.MMIO_READ, RelationType.MMIO_WRITE}:
            continue
        item = evidence_by_id[edge.evidence_ids[0]]
        observed.add(
            (
                edge.relation.value,
                item.address,
                item.instruction,
                item.metadata["resolved_target_address"],
                item.metadata["memory_map_region"],
            )
        )
        assert item.type is EvidenceType.STATIC_ANALYSIS
        assert item.source == "angr_analyzer"
        assert item.artifact == ARTIFACT_ID
        assert item.confidence == 1.0
        assert item.verified is True
        assert item.metadata["resolver"] == "vex_block_constant_propagation"
        assert item.metadata["resolved"] is True

    assert observed == {
        (
            "mmio_write",
            "0x10008",
            "str r0, [r1]",
            "0x40000000",
            "fixture-mmio-register",
        ),
        (
            "mmio_write",
            "0x1000c",
            "str r0, [r1]",
            "0x40000000",
            "fixture-mmio-register",
        ),
        (
            "mmio_read",
            "0x10010",
            "ldr r4, [r1]",
            "0x40000000",
            "fixture-mmio-register",
        ),
    }


def test_ram_and_unresolved_accesses_do_not_create_mmio_edges(
    mmio_result: ProgramAnalysisResult,
) -> None:
    """RAM and symbolic effective addresses remain diagnostics, never guessed edges."""

    mmio_evidence = [
        item
        for item in mmio_result.evidence
        if item.metadata.get("observation") in {"mmio_read", "mmio_write"}
    ]

    assert mmio_result.metadata["non_mmio_memory_accesses"] == 2
    assert mmio_result.metadata["unresolved_memory_accesses"] == 2
    assert all(
        item.metadata["resolved_target_address"] != "0x20001000"
        for item in mmio_evidence
    )
    assert {item.address for item in mmio_evidence}.isdisjoint(
        {"0x1001c", "0x10020", "0x10024", "0x10028"}
    )


def test_hardware_register_is_generated_once_and_reused(
    mmio_result: ProgramAnalysisResult,
) -> None:
    """Three accesses to one configured register share one deterministic node."""

    hardware_nodes = [
        node for node in mmio_result.nodes if node.layer is Layer.HARDWARE
    ]
    mmio_edges = [
        edge
        for edge in mmio_result.edges
        if edge.relation in {RelationType.MMIO_READ, RelationType.MMIO_WRITE}
    ]

    assert len(hardware_nodes) == 1
    register = hardware_nodes[0]
    assert register.id == HARDWARE_NODE_ID
    assert register.kind is NodeKind.REGISTER
    assert register.name == "FIXTURE_MMIO_REGISTER"
    assert register.address == "0x40000000"
    assert register.layer is Layer.HARDWARE
    assert {edge.target_id for edge in mmio_edges} == {register.id}


def test_phase4b_and_phase5_hardware_match_keys_agree(
    mmio_result: ProgramAnalysisResult,
) -> None:
    """The actual analyzer node and KG fixture share exact keys, not node IDs."""

    behavior_resource = next(
        node for node in mmio_result.nodes if node.layer is Layer.HARDWARE
    )
    sample = VulnerabilitySample.model_validate_json(
        (
            Path(__file__).parent
            / "fixtures"
            / "knowledge"
            / "synthetic_arm_vulnerability.json"
        ).read_text(encoding="utf-8")
    )
    knowledge_resource = next(
        node
        for node in VulnerabilityKnowledgeBuilder().build(sample).nodes
        if node.kind is KnowledgeNodeKind.HARDWARE_RESOURCE
    )
    behavior_keys = hardware_resource_match_keys(
        behavior_resource.architecture,
        address=behavior_resource.address,
        metadata=behavior_resource.metadata,
    )

    assert behavior_resource.id != knowledge_resource.id
    assert behavior_keys == knowledge_resource.match_keys


def test_mmio_evidence_references_are_complete(
    mmio_result: ProgramAnalysisResult,
) -> None:
    """Every generated Edge must reference evidence retained in the result."""

    evidence_ids = {item.id for item in mmio_result.evidence}

    assert len(evidence_ids) == 4
    assert all(edge.evidence_ids for edge in mmio_result.edges)
    assert all(
        set(edge.evidence_ids).issubset(evidence_ids) for edge in mmio_result.edges
    )


def test_empty_map_produces_no_mmio_but_keeps_memory_diagnostics(
    driver_artifact: ProgramArtifact,
) -> None:
    """An explicit empty map cannot classify any concrete address as MMIO."""

    empty_map = MemoryMap(id="empty-arm-map", architecture="arm")
    result = AngrAnalyzer(memory_map=empty_map).analyze(driver_artifact)

    assert all(node.layer is not Layer.HARDWARE for node in result.nodes)
    assert all(
        edge.relation not in {RelationType.MMIO_READ, RelationType.MMIO_WRITE}
        for edge in result.edges
    )
    assert result.metadata["resolved_mmio_accesses"] == 0
    assert result.metadata["non_mmio_memory_accesses"] == 5
    assert result.metadata["unresolved_memory_accesses"] == 2
    assert result.metadata["resolved_call_count"] == 1


def test_memory_map_architecture_mismatch_is_rejected(
    driver_artifact: ProgramArtifact,
) -> None:
    """A device map from another architecture cannot classify an ARM artifact."""

    wrong_map = MemoryMap(id="risc-v-map", architecture="risc_v")

    with pytest.raises(InvalidAnalysisInputError, match="architecture"):
        AngrAnalyzer(memory_map=wrong_map).analyze(driver_artifact)


def test_mmio_result_is_deterministic_and_round_trips(
    driver_artifact: ProgramArtifact,
    mmio_memory_map: MemoryMap,
) -> None:
    """ELF, map, and configuration yield stable IDs, ordering, and JSON."""

    analyzer = AngrAnalyzer(memory_map=mmio_memory_map)
    first = analyzer.analyze(driver_artifact)
    second = analyzer.analyze(driver_artifact)
    restored = ProgramAnalysisResult.model_validate_json(first.model_dump_json())

    assert first == second == restored
    assert [node.id for node in first.nodes] == sorted(node.id for node in first.nodes)
    assert [edge.id for edge in first.edges] == sorted(edge.id for edge in first.edges)
    assert [item.id for item in first.evidence] == sorted(
        item.id for item in first.evidence
    )


def test_driver_to_hardware_graph_path_uses_existing_ingestion(
    mmio_result: ProgramAnalysisResult,
) -> None:
    """Machine-code CALLS and MMIO facts form a real cross-layer GraphPath."""

    repository = NetworkXGraphRepository()
    ingest_analysis_result(mmio_result, repository)
    paths = repository.find_paths(
        f"{ARTIFACT_ID}:function:00010030",
        target_id=HARDWARE_NODE_ID,
        architecture=Architecture.ARM,
        max_hops=2,
        allowed_layers={Layer.DRIVER, Layer.HARDWARE},
    )

    assert len(paths) == 3
    assert all(
        path.node_ids
        == [
            f"{ARTIFACT_ID}:function:00010030",
            f"{ARTIFACT_ID}:function:00010000",
            HARDWARE_NODE_ID,
        ]
        for path in paths
    )
    assert all(path.hop_count == 2 for path in paths)


def test_mmio_demo_reports_cross_layer_observation_without_security_claims() -> None:
    """The runnable demo reports only machine-code-derived behavior facts."""

    repository_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [sys.executable, "examples/arm_angr_mmio_demo.py"],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "Artifact: synthetic-arm-mmio" in completed.stdout
    assert "Program Layer: driver" in completed.stdout
    assert "Functions recovered: 2" in completed.stdout
    assert "Calls recovered: 1" in completed.stdout
    assert "Resolved MMIO accesses: 3" in completed.stdout
    assert "Unresolved memory accesses: 2" in completed.stdout
    assert (
        "Path: main -> driver_like_function -> FIXTURE_MMIO_REGISTER"
        in completed.stdout
    )
    assert "MMIO instruction: str r0, [r1]" in completed.stdout
    assert "Resolved address: 0x40000000" in completed.stdout
    assert "Memory map region: fixture-mmio-register" in completed.stdout
    for forbidden_claim in (
        "Vulnerability Found",
        "Hardware Weakness Found",
        "Exploit Confirmed",
        "Privilege Escalation",
    ):
        assert forbidden_claim not in completed.stdout
