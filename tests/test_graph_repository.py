"""Tests for GraphRepository mutation, lookup, and filter invariants."""

from __future__ import annotations

import networkx as nx
import pytest

from chipchain.graph import (
    ArchitectureMismatchError,
    DuplicateEdgeError,
    DuplicateNodeError,
    EdgeNotFoundError,
    NetworkXGraphRepository,
    NodeNotFoundError,
)
from chipchain.models import (
    Architecture,
    BehaviorEdge,
    BehaviorNode,
    Layer,
    NodeKind,
    RelationType,
)


def make_node(
    node_id: str,
    *,
    architecture: Architecture = Architecture.ARM,
    layer: Layer = Layer.FIRMWARE,
) -> BehaviorNode:
    """Build a small synthetic graph node."""

    return BehaviorNode(
        id=node_id,
        kind=NodeKind.FUNCTION,
        name=node_id,
        architecture=architecture,
        layer=layer,
        metadata={"fixture": True},
    )


def make_edge(
    edge_id: str,
    source_id: str,
    target_id: str,
    *,
    architecture: Architecture = Architecture.ARM,
    relation: RelationType = RelationType.CALLS,
) -> BehaviorEdge:
    """Build a small synthetic graph edge."""

    return BehaviorEdge(
        id=edge_id,
        source_id=source_id,
        target_id=target_id,
        relation=relation,
        architecture=architecture,
        evidence_ids=[f"{edge_id}-evidence"],
        metadata={"fixture": True},
    )


def test_backend_is_multidigraph_and_add_get_node() -> None:
    """The backend must be MultiDiGraph and return the added domain node."""

    repository = NetworkXGraphRepository()
    node = make_node("fixture-a")

    repository.add_node(node)

    assert isinstance(repository._graph, nx.MultiDiGraph)
    assert repository.get_node(node.id) == node


def test_add_get_edge_preserves_evidence_ids() -> None:
    """Edges should be retrievable by global ID with evidence references intact."""

    repository = NetworkXGraphRepository()
    repository.add_node(make_node("fixture-a"))
    repository.add_node(make_node("fixture-b", layer=Layer.DRIVER))
    edge = make_edge("fixture-edge", "fixture-a", "fixture-b")

    repository.add_edge(edge)

    assert repository.get_edge(edge.id) == edge
    assert repository.get_edge(edge.id).evidence_ids == [
        "fixture-edge-evidence"
    ]


def test_duplicate_node_id_is_rejected() -> None:
    """Node insertion must never silently overwrite existing data."""

    repository = NetworkXGraphRepository()
    repository.add_node(make_node("fixture-a"))

    with pytest.raises(DuplicateNodeError):
        repository.add_node(make_node("fixture-a", layer=Layer.DRIVER))


def test_duplicate_edge_id_is_rejected_globally() -> None:
    """An edge ID cannot be reused even for another endpoint pair."""

    repository = NetworkXGraphRepository()
    for node_id in ("fixture-a", "fixture-b", "fixture-c"):
        repository.add_node(make_node(node_id))
    repository.add_edge(make_edge("fixture-edge", "fixture-a", "fixture-b"))

    with pytest.raises(DuplicateEdgeError):
        repository.add_edge(make_edge("fixture-edge", "fixture-b", "fixture-c"))


@pytest.mark.parametrize(
    ("source_id", "target_id", "message"),
    [
        ("missing-source", "fixture-b", "source node"),
        ("fixture-a", "missing-target", "target node"),
    ],
)
def test_dangling_edge_endpoint_is_rejected(
    source_id: str, target_id: str, message: str
) -> None:
    """Both endpoints must exist before an edge can be added."""

    repository = NetworkXGraphRepository()
    repository.add_node(make_node("fixture-a"))
    repository.add_node(make_node("fixture-b"))

    with pytest.raises(NodeNotFoundError, match=message):
        repository.add_edge(make_edge("fixture-edge", source_id, target_id))


def test_cross_architecture_edge_is_rejected() -> None:
    """An ARM edge cannot connect an ARM node to a RISC-V node."""

    repository = NetworkXGraphRepository()
    repository.add_node(make_node("fixture-arm"))
    repository.add_node(
        make_node("fixture-riscv", architecture=Architecture.RISC_V)
    )

    with pytest.raises(ArchitectureMismatchError):
        repository.add_edge(
            make_edge("fixture-cross-architecture", "fixture-arm", "fixture-riscv")
        )


def test_parallel_edges_between_same_nodes_are_preserved() -> None:
    """Different relations between A and B must coexist in MultiDiGraph."""

    repository = NetworkXGraphRepository()
    repository.add_node(make_node("fixture-a"))
    repository.add_node(make_node("fixture-b"))
    repository.add_edge(
        make_edge(
            "fixture-edge-calls",
            "fixture-a",
            "fixture-b",
            relation=RelationType.CALLS,
        )
    )
    repository.add_edge(
        make_edge(
            "fixture-edge-data",
            "fixture-a",
            "fixture-b",
            relation=RelationType.DATA_FLOWS_TO,
        )
    )

    assert [edge.id for edge in repository.list_edges()] == [
        "fixture-edge-calls",
        "fixture-edge-data",
    ]
    assert repository._graph.number_of_edges("fixture-a", "fixture-b") == 2


def test_node_architecture_and_layer_filters(
    arm_demo_graph: NetworkXGraphRepository,
) -> None:
    """Architecture and allowed-layer filters combine with AND semantics."""

    arm_demo_graph.add_node(
        make_node(
            "fixture-riscv",
            architecture=Architecture.RISC_V,
            layer=Layer.FIRMWARE,
        )
    )

    arm_nodes = arm_demo_graph.list_nodes(architecture=Architecture.ARM)
    hardware_nodes = arm_demo_graph.list_nodes(
        allowed_layers={Layer.HARDWARE}
    )
    arm_firmware_nodes = arm_demo_graph.list_nodes(
        architecture=Architecture.ARM,
        allowed_layers={Layer.FIRMWARE},
    )

    assert all(node.architecture is Architecture.ARM for node in arm_nodes)
    assert {node.id for node in hardware_nodes} == {
        "fixture_debug_ctrl",
        "fixture_hardware_weakness",
    }
    assert [node.id for node in arm_firmware_nodes] == ["fixture_parse_command"]


def test_successors_and_predecessors_follow_direction(
    arm_demo_graph: NetworkXGraphRepository,
) -> None:
    """Parallel edges do not duplicate adjacent nodes and direction is respected."""

    assert [node.id for node in arm_demo_graph.successors("fixture_parse_command")] == [
        "fixture_ioctl"
    ]
    assert [node.id for node in arm_demo_graph.predecessors("fixture_ioctl")] == [
        "fixture_parse_command"
    ]
    assert arm_demo_graph.predecessors("fixture_parse_command") == []


def test_remove_edge_preserves_parallel_edge() -> None:
    """Removing one relation must not remove a parallel relation."""

    repository = NetworkXGraphRepository()
    repository.add_node(make_node("fixture-a"))
    repository.add_node(make_node("fixture-b"))
    first = make_edge("fixture-edge-a", "fixture-a", "fixture-b")
    second = make_edge(
        "fixture-edge-b",
        "fixture-a",
        "fixture-b",
        relation=RelationType.DATA_FLOWS_TO,
    )
    repository.add_edge(first)
    repository.add_edge(second)

    assert repository.remove_edge(first.id) == first
    assert repository.get_edge(second.id) == second
    with pytest.raises(EdgeNotFoundError):
        repository.get_edge(first.id)


def test_remove_node_cleans_incident_edge_index(
    arm_demo_graph: NetworkXGraphRepository,
) -> None:
    """Removing a node must remove all incoming and outgoing edge lookups."""

    removed = arm_demo_graph.remove_node("fixture_ioctl")

    assert removed.id == "fixture_ioctl"
    with pytest.raises(NodeNotFoundError):
        arm_demo_graph.get_node("fixture_ioctl")
    for edge_id in (
        "fixture_edge_issues_ioctl",
        "fixture_edge_data_to_ioctl",
        "fixture_edge_invokes_driver",
    ):
        with pytest.raises(EdgeNotFoundError):
            arm_demo_graph.get_edge(edge_id)
