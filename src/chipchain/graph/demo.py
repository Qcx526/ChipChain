"""Deterministic ARM fixture graph used by examples and tests."""

from __future__ import annotations

from chipchain.graph.networkx_repository import NetworkXGraphRepository
from chipchain.models import (
    Architecture,
    BehaviorEdge,
    BehaviorNode,
    Layer,
    NodeKind,
    RelationType,
)


def build_arm_demo_graph() -> NetworkXGraphRepository:
    """Build a synthetic ARM behavior graph with no real vulnerability claims."""

    repository = NetworkXGraphRepository(
        metadata={
            "sample_type": "fixture",
            "source": "chipchain-arm-graph-fixture",
            "real_vulnerability": False,
        }
    )
    nodes = [
        BehaviorNode(
            id="fixture_parse_command",
            kind=NodeKind.FUNCTION,
            name="fixture_parse_command",
            architecture=Architecture.ARM,
            layer=Layer.FIRMWARE,
            metadata={"fixture": True},
        ),
        BehaviorNode(
            id="fixture_ioctl",
            kind=NodeKind.INTERFACE,
            name="FIXTURE_IOCTL_SET_DEBUG",
            architecture=Architecture.ARM,
            layer=Layer.INTERFACE,
            metadata={"fixture": True},
        ),
        BehaviorNode(
            id="fixture_driver_ioctl",
            kind=NodeKind.DRIVER_FUNCTION,
            name="fixture_driver_ioctl",
            architecture=Architecture.ARM,
            layer=Layer.DRIVER,
            metadata={"fixture": True},
        ),
        BehaviorNode(
            id="fixture_debug_ctrl",
            kind=NodeKind.REGISTER,
            name="FIXTURE_DEBUG_CTRL",
            architecture=Architecture.ARM,
            layer=Layer.HARDWARE,
            address="0x50000000",
            metadata={"fixture": True},
        ),
        BehaviorNode(
            id="fixture_hardware_weakness",
            kind=NodeKind.WEAKNESS,
            name="Fixture Hardware Weakness",
            architecture=Architecture.ARM,
            layer=Layer.HARDWARE,
            metadata={"fixture": True},
        ),
        BehaviorNode(
            id="fixture_privilege_impact",
            kind=NodeKind.IMPACT,
            name="Fixture Privilege Impact",
            architecture=Architecture.ARM,
            layer=Layer.IMPACT,
            metadata={"fixture": True},
        ),
    ]
    for node in nodes:
        repository.add_node(node)

    edges = [
        BehaviorEdge(
            id="fixture_edge_issues_ioctl",
            source_id="fixture_parse_command",
            target_id="fixture_ioctl",
            relation=RelationType.ISSUES,
            architecture=Architecture.ARM,
            evidence_ids=["fixture_evidence_ioctl_issue"],
            metadata={"fixture": True},
        ),
        BehaviorEdge(
            id="fixture_edge_data_to_ioctl",
            source_id="fixture_parse_command",
            target_id="fixture_ioctl",
            relation=RelationType.DATA_FLOWS_TO,
            architecture=Architecture.ARM,
            evidence_ids=["fixture_evidence_ioctl_data"],
            metadata={"fixture": True},
        ),
        BehaviorEdge(
            id="fixture_edge_invokes_driver",
            source_id="fixture_ioctl",
            target_id="fixture_driver_ioctl",
            relation=RelationType.INVOKES,
            architecture=Architecture.ARM,
            evidence_ids=["fixture_evidence_driver_invoke"],
            metadata={"fixture": True},
        ),
        BehaviorEdge(
            id="fixture_edge_mmio_write",
            source_id="fixture_driver_ioctl",
            target_id="fixture_debug_ctrl",
            relation=RelationType.MMIO_WRITE,
            architecture=Architecture.ARM,
            evidence_ids=["fixture_evidence_mmio_write"],
            metadata={"fixture": True},
        ),
        BehaviorEdge(
            id="fixture_edge_register_to_weakness",
            source_id="fixture_debug_ctrl",
            target_id="fixture_hardware_weakness",
            relation=RelationType.LEADS_TO,
            architecture=Architecture.ARM,
            evidence_ids=["fixture_evidence_register_relation"],
            metadata={"fixture": True},
        ),
        BehaviorEdge(
            id="fixture_edge_weakness_to_impact",
            source_id="fixture_hardware_weakness",
            target_id="fixture_privilege_impact",
            relation=RelationType.LEADS_TO,
            architecture=Architecture.ARM,
            evidence_ids=["fixture_evidence_impact_relation"],
            metadata={"fixture": True},
        ),
    ]
    for edge in edges:
        repository.add_edge(edge)
    return repository
