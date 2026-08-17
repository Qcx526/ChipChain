"""Tests for preflight, rollback, and end-to-end analysis ingestion."""

from __future__ import annotations

import pytest

from chipchain.analysis import (
    AnalysisIngestionError,
    ProgramAnalysisResult,
    ingest_analysis_result,
)
from chipchain.graph import NetworkXGraphRepository
from chipchain.models import (
    Architecture,
    BehaviorEdge,
    BehaviorNode,
    Layer,
    NodeKind,
    RelationType,
)


def test_analysis_result_ingests_into_graph_repository(
    demo_analysis_result: ProgramAnalysisResult,
) -> None:
    """Ingestion writes nodes and edges while the result retains Evidence objects."""

    repository = NetworkXGraphRepository()

    ingest_analysis_result(demo_analysis_result, repository)

    assert repository.list_nodes() == demo_analysis_result.nodes
    assert repository.list_edges() == demo_analysis_result.edges
    assert repository.get_edge(
        "fixture-mmio-access-mmio_write"
    ).evidence_ids == ["fixture-mmio-access-evidence"]


def test_end_to_end_analysis_produces_expected_graph_path(
    demo_analysis_result: ProgramAnalysisResult,
) -> None:
    """Fixture spec reaches the ARM register through analyzer and repository layers."""

    repository = NetworkXGraphRepository()
    ingest_analysis_result(demo_analysis_result, repository)

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

    assert len(paths) == 1
    assert paths[0].node_ids == [
        "fixture_parse_command",
        "fixture_ioctl",
        "fixture_driver_ioctl",
        "fixture_debug_ctrl",
    ]
    assert paths[0].edge_ids == [
        "fixture-ioctl-flow-issues",
        "fixture-ioctl-flow-invokes",
        "fixture-mmio-access-mmio_write",
    ]
    assert paths[0].hop_count == 3


def test_duplicate_node_collision_is_rejected_without_partial_mutation(
    demo_analysis_result: ProgramAnalysisResult,
) -> None:
    """Preflight catches one conflicting node before writing any other node."""

    repository = NetworkXGraphRepository()
    existing = BehaviorNode(
        id="fixture_driver_ioctl",
        kind=NodeKind.DRIVER_FUNCTION,
        name="existing_fixture_driver",
        architecture=Architecture.ARM,
        layer=Layer.DRIVER,
    )
    repository.add_node(existing)
    before_nodes = repository.list_nodes()
    before_edges = repository.list_edges()

    with pytest.raises(AnalysisIngestionError, match="node IDs"):
        ingest_analysis_result(demo_analysis_result, repository)

    assert repository.list_nodes() == before_nodes
    assert repository.list_edges() == before_edges


def test_duplicate_edge_collision_is_rejected_without_partial_mutation(
    demo_analysis_result: ProgramAnalysisResult,
) -> None:
    """A conflicting Edge ID is detected before result nodes are inserted."""

    repository = NetworkXGraphRepository()
    for node_id in ("existing-a", "existing-b"):
        repository.add_node(
            BehaviorNode(
                id=node_id,
                kind=NodeKind.FUNCTION,
                name=node_id,
                architecture=Architecture.ARM,
                layer=Layer.FIRMWARE,
            )
        )
    repository.add_edge(
        BehaviorEdge(
            id="fixture-ioctl-flow-issues",
            source_id="existing-a",
            target_id="existing-b",
            relation=RelationType.CALLS,
            architecture=Architecture.ARM,
        )
    )
    before_nodes = repository.list_nodes()
    before_edges = repository.list_edges()

    with pytest.raises(AnalysisIngestionError, match="edge IDs"):
        ingest_analysis_result(demo_analysis_result, repository)

    assert repository.list_nodes() == before_nodes
    assert repository.list_edges() == before_edges


def test_unexpected_backend_failure_rolls_back_inserted_data(
    demo_analysis_result: ProgramAnalysisResult,
) -> None:
    """Defensive rollback removes successful writes before a backend failure."""

    class FailingRepository(NetworkXGraphRepository):
        def add_edge(self, edge: BehaviorEdge) -> None:
            if edge.id == "fixture-ioctl-flow-invokes":
                raise RuntimeError("fixture backend failure")
            super().add_edge(edge)

    repository = FailingRepository()

    with pytest.raises(AnalysisIngestionError, match="rolled back"):
        ingest_analysis_result(demo_analysis_result, repository)

    assert repository.list_nodes() == []
    assert repository.list_edges() == []


def test_mutated_invalid_result_is_revalidated_before_ingestion(
    demo_analysis_result: ProgramAnalysisResult,
) -> None:
    """Nested in-place mutation cannot bypass preflight result validation."""

    demo_analysis_result.edges[0].evidence_ids[:] = ["missing-evidence"]
    repository = NetworkXGraphRepository()

    with pytest.raises(AnalysisIngestionError, match="preflight validation"):
        ingest_analysis_result(demo_analysis_result, repository)

    assert repository.list_nodes() == []
    assert repository.list_edges() == []
