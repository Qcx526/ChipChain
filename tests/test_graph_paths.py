"""Tests for deterministic directed simple-path search semantics."""

from __future__ import annotations

import pytest

from chipchain.graph import GraphPath, NetworkXGraphRepository
from chipchain.models import (
    Architecture,
    AttackChain,
    BehaviorEdge,
    BehaviorNode,
    Layer,
    NodeKind,
    RelationType,
)

ARM_PATH_LAYERS = {
    Layer.FIRMWARE,
    Layer.INTERFACE,
    Layer.DRIVER,
    Layer.HARDWARE,
}


def query_register_paths(
    repository: NetworkXGraphRepository,
    **overrides: object,
) -> list[GraphPath]:
    """Query the demo firmware-to-register paths with overrideable options."""

    options: dict[str, object] = {
        "target_id": "fixture_debug_ctrl",
        "architecture": Architecture.ARM,
        "max_hops": 3,
        "allowed_layers": ARM_PATH_LAYERS,
    }
    options.update(overrides)
    return repository.find_paths("fixture_parse_command", **options)  # type: ignore[arg-type]


def test_directed_path_search_returns_graph_paths_not_attack_chains(
    arm_demo_graph: NetworkXGraphRepository,
) -> None:
    """Phase 2 returns structural GraphPath objects in edge direction only."""

    paths = query_register_paths(arm_demo_graph)
    reverse = arm_demo_graph.find_paths(
        "fixture_debug_ctrl",
        target_id="fixture_parse_command",
        architecture=Architecture.ARM,
        max_hops=3,
    )

    assert len(paths) == 2
    assert all(isinstance(path, GraphPath) for path in paths)
    assert all(not isinstance(path, AttackChain) for path in paths)
    assert reverse == []


def test_max_hops_counts_edges_not_nodes(
    arm_demo_graph: NetworkXGraphRepository,
) -> None:
    """The three-edge firmware-to-register path needs max_hops >= 3."""

    assert query_register_paths(arm_demo_graph, max_hops=2) == []
    assert {path.hop_count for path in query_register_paths(arm_demo_graph)} == {3}


def test_simple_path_search_never_repeats_cycle_nodes(
    arm_demo_graph: NetworkXGraphRepository,
) -> None:
    """A back edge may exist, but no returned path may revisit a node."""

    arm_demo_graph.add_edge(
        BehaviorEdge(
            id="fixture_cycle_edge",
            source_id="fixture_privilege_impact",
            target_id="fixture_parse_command",
            relation=RelationType.LEADS_TO,
            architecture=Architecture.ARM,
        )
    )

    paths = arm_demo_graph.find_paths(
        "fixture_parse_command",
        architecture=Architecture.ARM,
        max_hops=8,
    )

    assert paths
    assert all(len(path.node_ids) == len(set(path.node_ids)) for path in paths)


def test_architecture_is_enforced_during_path_search(
    arm_demo_graph: NetworkXGraphRepository,
) -> None:
    """A RISC-V start component cannot participate in an ARM query."""

    for node_id in ("fixture-riscv-a", "fixture-riscv-b"):
        arm_demo_graph.add_node(
            BehaviorNode(
                id=node_id,
                kind=NodeKind.FUNCTION,
                name=node_id,
                architecture=Architecture.RISC_V,
                layer=Layer.FIRMWARE,
            )
        )
    arm_demo_graph.add_edge(
        BehaviorEdge(
            id="fixture-riscv-edge",
            source_id="fixture-riscv-a",
            target_id="fixture-riscv-b",
            relation=RelationType.CALLS,
            architecture=Architecture.RISC_V,
        )
    )

    assert (
        arm_demo_graph.find_paths(
            "fixture-riscv-a",
            architecture=Architecture.ARM,
            max_hops=1,
        )
        == []
    )
    risc_paths = arm_demo_graph.find_paths(
        "fixture-riscv-a",
        architecture=Architecture.RISC_V,
        max_hops=1,
    )
    assert [path.node_ids for path in risc_paths] == [
        ["fixture-riscv-a", "fixture-riscv-b"]
    ]


def test_allowed_layers_apply_to_every_path_node(
    arm_demo_graph: NetworkXGraphRepository,
) -> None:
    """Excluding the driver layer prevents the firmware-to-hardware path."""

    paths = query_register_paths(
        arm_demo_graph,
        allowed_layers={Layer.FIRMWARE, Layer.INTERFACE, Layer.HARDWARE},
    )

    assert paths == []


def test_max_results_is_applied_after_deterministic_sorting(
    arm_demo_graph: NetworkXGraphRepository,
) -> None:
    """Parallel alternatives are stable and max_results returns the first one."""

    all_paths = query_register_paths(arm_demo_graph)
    limited = query_register_paths(arm_demo_graph, max_results=1)

    assert [path.edge_ids[0] for path in all_paths] == [
        "fixture_edge_data_to_ioctl",
        "fixture_edge_issues_ioctl",
    ]
    assert limited == all_paths[:1]


def test_path_result_order_is_independent_of_insertion_order() -> None:
    """Equivalent graphs built in different orders return identical path ordering."""

    def build(edge_order: list[str]) -> NetworkXGraphRepository:
        repository = NetworkXGraphRepository()
        for node_id in ("a", "b", "c"):
            repository.add_node(
                BehaviorNode(
                    id=node_id,
                    kind=NodeKind.FUNCTION,
                    name=node_id,
                    architecture=Architecture.ARM,
                    layer=Layer.FIRMWARE,
                )
            )
        edges = {
            "z-edge": BehaviorEdge(
                id="z-edge",
                source_id="a",
                target_id="b",
                relation=RelationType.CALLS,
                architecture=Architecture.ARM,
            ),
            "a-edge": BehaviorEdge(
                id="a-edge",
                source_id="a",
                target_id="b",
                relation=RelationType.DATA_FLOWS_TO,
                architecture=Architecture.ARM,
            ),
            "b-edge": BehaviorEdge(
                id="b-edge",
                source_id="b",
                target_id="c",
                relation=RelationType.CALLS,
                architecture=Architecture.ARM,
            ),
        }
        for edge_id in edge_order:
            repository.add_edge(edges[edge_id])
        return repository

    first = build(["z-edge", "a-edge", "b-edge"])
    second = build(["b-edge", "a-edge", "z-edge"])

    first_paths = first.find_paths(
        "a", target_id="c", architecture=Architecture.ARM, max_hops=2
    )
    second_paths = second.find_paths(
        "a", target_id="c", architecture=Architecture.ARM, max_hops=2
    )

    assert first_paths == second_paths
    assert [path.edge_ids for path in first_paths] == [
        ["a-edge", "b-edge"],
        ["z-edge", "b-edge"],
    ]


def test_targetless_search_returns_paths_in_hop_then_id_order(
    arm_demo_graph: NetworkXGraphRepository,
) -> None:
    """Without a target, all non-empty reachable paths are deterministically sorted."""

    paths = arm_demo_graph.find_paths(
        "fixture_parse_command",
        architecture=Architecture.ARM,
        max_hops=2,
    )

    assert [path.hop_count for path in paths] == sorted(
        path.hop_count for path in paths
    )
    assert {path.hop_count for path in paths} == {1, 2}


def test_zero_hop_path_is_valid_only_for_same_target(
    arm_demo_graph: NetworkXGraphRepository,
) -> None:
    """A start-to-itself target is represented by one node and no edges."""

    paths = arm_demo_graph.find_paths(
        "fixture_parse_command",
        target_id="fixture_parse_command",
        architecture=Architecture.ARM,
        max_hops=0,
    )

    assert paths == [
        GraphPath(
            architecture=Architecture.ARM,
            node_ids=["fixture_parse_command"],
            edge_ids=[],
            hop_count=0,
        )
    ]


@pytest.mark.parametrize(
    ("max_hops", "max_results"),
    [(-1, None), (1, 0), (1, -1)],
)
def test_invalid_search_limits_are_rejected(
    arm_demo_graph: NetworkXGraphRepository,
    max_hops: int,
    max_results: int | None,
) -> None:
    """Negative depth and non-positive result limits have no valid semantics."""

    with pytest.raises(ValueError):
        arm_demo_graph.find_paths(
            "fixture_parse_command",
            architecture=Architecture.ARM,
            max_hops=max_hops,
            max_results=max_results,
        )
