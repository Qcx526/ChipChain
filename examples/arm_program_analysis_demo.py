"""Run the fixture ProgramAnalyzer-to-GraphRepository ARM pipeline."""

from __future__ import annotations

from pathlib import Path

from chipchain.analysis import DemoAnalyzer, ProgramArtifact, ingest_analysis_result
from chipchain.graph import NetworkXGraphRepository
from chipchain.models import Architecture, Layer, NodeKind, RelationType


def main() -> int:
    """Analyze the auditable fixture, ingest observations, and query a GraphPath."""

    project_root = Path(__file__).resolve().parents[1]
    fixture_path = (
        project_root
        / "tests"
        / "fixtures"
        / "program_analysis"
        / "arm_demo_program.json"
    )
    artifact = ProgramArtifact(
        id="fixture-arm-program",
        architecture=Architecture.ARM,
        artifact_type="fixture",
        path=str(fixture_path),
        fixture_identifier="fixture-arm-demo-program-spec",
        metadata={"fixture": True, "real_program": False},
    )
    result = DemoAnalyzer().analyze(artifact)

    function_nodes = [
        node
        for node in result.nodes
        if node.kind in {NodeKind.FUNCTION, NodeKind.DRIVER_FUNCTION}
    ]
    interface_nodes = [node for node in result.nodes if node.kind is NodeKind.INTERFACE]
    call_edges = [edge for edge in result.edges if edge.relation is RelationType.CALLS]
    mmio_edges = [
        edge
        for edge in result.edges
        if edge.relation in {RelationType.MMIO_READ, RelationType.MMIO_WRITE}
    ]

    print(f"Discovered functions: {len(function_nodes)}")
    print(f"Discovered interfaces: {len(interface_nodes)}")
    print(f"Call relations: {len(call_edges)}")
    print(f"MMIO accesses: {len(mmio_edges)}")
    print(f"Evidence count: {len(result.evidence)}")
    sensitive = [
        node.id for node in function_nodes if node.metadata.get("sensitive") is True
    ]
    print(f"Sensitive markers: {', '.join(sensitive)}")

    repository = NetworkXGraphRepository(
        metadata={"source": "demo_analyzer", "fixture": True}
    )
    ingest_analysis_result(result, repository)
    paths = repository.find_paths(
        "fixture_parse_command",
        target_id="fixture_debug_ctrl",
        architecture=Architecture.ARM,
        max_hops=3,
        allowed_layers={
            Layer.FIRMWARE,
            Layer.INTERFACE,
            Layer.DRIVER,
            Layer.HARDWARE,
        },
    )
    if not paths:
        raise RuntimeError("fixture analysis did not produce the expected GraphPath")
    path = paths[0]
    print(f"Node path: {' -> '.join(path.node_ids)}")
    print(f"Edge path: {' -> '.join(path.edge_ids)}")
    print(f"Hop count: {path.hop_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
