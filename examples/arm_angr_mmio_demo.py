"""Recover a real ARM driver-to-hardware observation from synthetic machine code."""

from __future__ import annotations

from pathlib import Path

from chipchain.analysis import (
    AngrAnalyzer,
    MemoryMap,
    ProgramArtifact,
    ingest_analysis_result,
)
from chipchain.graph import NetworkXGraphRepository
from chipchain.models import Architecture, Layer, RelationType


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIRECTORY = (
    REPOSITORY_ROOT / "tests" / "fixtures" / "angr" / "arm_mmio"
)
ARTIFACT_ID = "synthetic-arm-mmio"
HARDWARE_NODE_ID = (
    f"{ARTIFACT_ID}:memory-map:synthetic-arm-mmio-map:"
    "region:fixture-mmio-register"
)


def main() -> None:
    """Run ARM ELF → VEX address resolution → MMIO GraphPath."""

    memory_map = MemoryMap.model_validate_json(
        (FIXTURE_DIRECTORY / "memory_map.json").read_text(encoding="utf-8")
    )
    artifact = ProgramArtifact(
        id=ARTIFACT_ID,
        architecture=Architecture.ARM,
        artifact_type="elf",
        program_layer=Layer.DRIVER,
        path=str(FIXTURE_DIRECTORY / "arm_mmio.elf"),
        fixture_identifier="synthetic-arm-mmio-elf",
        metadata={"fixture": True, "synthetic": True, "owned": True},
    )
    result = AngrAnalyzer(memory_map=memory_map).analyze(artifact)
    repository = NetworkXGraphRepository()
    ingest_analysis_result(result, repository)
    paths = repository.find_paths(
        f"{ARTIFACT_ID}:function:00010030",
        target_id=HARDWARE_NODE_ID,
        architecture=Architecture.ARM,
        max_hops=2,
        allowed_layers={Layer.DRIVER, Layer.HARDWARE},
    )
    write_path = next(
        path
        for path in paths
        if repository.get_edge(path.edge_ids[-1]).relation is RelationType.MMIO_WRITE
    )
    node_names = [repository.get_node(node_id).name for node_id in write_path.node_ids]
    mmio_edge = repository.get_edge(write_path.edge_ids[-1])
    evidence_by_id = {item.id: item for item in result.evidence}
    mmio_evidence = evidence_by_id[mmio_edge.evidence_ids[0]]

    print(f"Artifact: {artifact.id}")
    print(f"Program Layer: {artifact.program_layer.value}")
    print(f"Functions recovered: {result.metadata['function_count']}")
    print(f"Calls recovered: {result.metadata['resolved_call_count']}")
    print(f"Resolved MMIO accesses: {result.metadata['resolved_mmio_accesses']}")
    print(
        "Unresolved memory accesses: "
        f"{result.metadata['unresolved_memory_accesses']}"
    )
    print("Path: " + " -> ".join(node_names))
    print(f"MMIO instruction: {mmio_evidence.instruction}")
    print(
        "Resolved address: "
        f"{mmio_evidence.metadata['resolved_target_address']}"
    )
    print(f"Memory map region: {mmio_evidence.metadata['memory_map_region']}")


if __name__ == "__main__":
    main()
