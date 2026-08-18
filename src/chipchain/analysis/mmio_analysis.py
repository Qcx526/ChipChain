"""Normalize resolved memory observations into cross-layer domain facts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from chipchain.analysis.memory_map import MemoryMap, MemoryRegion
from chipchain.analysis.models import ProgramArtifact
from chipchain.analysis.vex_memory import (
    MemoryAccessObservation,
    recover_function_memory_accesses,
)
from chipchain.models import (
    BehaviorEdge,
    BehaviorNode,
    Evidence,
    EvidenceType,
    Layer,
    RelationType,
)


@dataclass(frozen=True)
class MMIOAnalysisParts:
    """Domain output fragments and diagnostics produced by MMIO classification."""

    nodes: list[BehaviorNode]
    edges: list[BehaviorEdge]
    evidence: list[Evidence]
    diagnostics: dict[str, int]


def recover_mmio_result_parts(
    *,
    artifact: ProgramArtifact,
    project: Any,
    functions: dict[int, Any],
    memory_map: MemoryMap,
) -> MMIOAnalysisParts:
    """Classify only VEX-resolved accesses against the explicit memory map."""

    observations = [
        observation
        for _, function in sorted(functions.items())
        for observation in recover_function_memory_accesses(project, function)
    ]
    matched: list[tuple[MemoryAccessObservation, MemoryRegion]] = []
    unresolved_memory_accesses = 0
    non_mmio_memory_accesses = 0
    for observation in observations:
        if observation.target_address is None:
            unresolved_memory_accesses += 1
            continue
        region = memory_map.find_region(observation.target_address)
        if region is None:
            non_mmio_memory_accesses += 1
            continue
        matched.append((observation, region))

    regions = {region.id: region for _, region in matched}
    nodes = [
        _make_hardware_node(
            artifact=artifact,
            memory_map=memory_map,
            region=region,
        )
        for _, region in sorted(regions.items())
    ]
    edges: list[BehaviorEdge] = []
    evidence: list[Evidence] = []
    for observation, region in sorted(
        matched,
        key=lambda item: (
            item[0].instruction_address,
            item[0].access_type,
            item[0].statement_index,
            item[1].id,
        ),
    ):
        target_address = int(observation.target_address)
        relation = (
            RelationType.MMIO_WRITE
            if observation.access_type == "write"
            else RelationType.MMIO_READ
        )
        edge_id = _mmio_edge_id(
            artifact_id=artifact.id,
            function_address=observation.function_address,
            instruction_address=observation.instruction_address,
            statement_index=observation.statement_index,
            access_type=observation.access_type,
        )
        evidence_id = f"{edge_id}:evidence"
        common_metadata = {
            "observation": relation.value,
            "backend": "angr",
            "resolved_target_address": hex(target_address),
            "memory_map_id": memory_map.id,
            "memory_map_region": region.id,
            "resolver": observation.resolver,
            "resolved": True,
            "fixture": bool(artifact.metadata.get("fixture", False)),
        }
        edges.append(
            BehaviorEdge(
                id=edge_id,
                source_id=_function_id(
                    artifact.id, observation.function_address
                ),
                target_id=hardware_node_id(
                    artifact.id, memory_map.id, region.id
                ),
                relation=relation,
                architecture=artifact.architecture,
                evidence_ids=[evidence_id],
                metadata={
                    "analyzer": "angr_analyzer",
                    "instruction_address": hex(observation.instruction_address),
                    **common_metadata,
                },
            )
        )
        evidence.append(
            Evidence(
                id=evidence_id,
                type=EvidenceType.STATIC_ANALYSIS,
                source="angr_analyzer",
                artifact=artifact.id,
                address=hex(observation.instruction_address),
                instruction=observation.instruction,
                confidence=1.0,
                verified=True,
                metadata={
                    "function_address": hex(observation.function_address),
                    **common_metadata,
                },
            )
        )

    return MMIOAnalysisParts(
        nodes=nodes,
        edges=edges,
        evidence=evidence,
        diagnostics={
            "resolved_mmio_accesses": len(edges),
            "unresolved_memory_accesses": unresolved_memory_accesses,
            "non_mmio_memory_accesses": non_mmio_memory_accesses,
        },
    )


def hardware_node_id(artifact_id: str, memory_map_id: str, region_id: str) -> str:
    """Return the deterministic identity for one artifact/map hardware region."""

    return f"{artifact_id}:memory-map:{memory_map_id}:region:{region_id}"


def _make_hardware_node(
    *,
    artifact: ProgramArtifact,
    memory_map: MemoryMap,
    region: MemoryRegion,
) -> BehaviorNode:
    exact_address = region.start if region.start == region.end else None
    return BehaviorNode(
        id=hardware_node_id(artifact.id, memory_map.id, region.id),
        kind=region.resource_kind,
        name=region.name,
        architecture=artifact.architecture,
        layer=Layer.HARDWARE,
        address=exact_address,
        metadata={
            "analyzer": "angr_analyzer",
            "backend": "angr",
            "memory_map_id": memory_map.id,
            "memory_map_region": region.id,
            "region_kind": region.kind.value,
            "region_start": region.start,
            "region_end": region.end,
            "fixture": bool(
                region.metadata.get("fixture", False)
                or artifact.metadata.get("fixture", False)
            ),
        },
    )


def _function_id(artifact_id: str, address: int) -> str:
    return f"{artifact_id}:function:{address:08x}"


def _mmio_edge_id(
    *,
    artifact_id: str,
    function_address: int,
    instruction_address: int,
    statement_index: int,
    access_type: str,
) -> str:
    return (
        f"{artifact_id}:mmio-{access_type}:{function_address:08x}:"
        f"{instruction_address:08x}:{statement_index}"
    )
