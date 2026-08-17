"""Tests for stable validated JSON graph persistence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx
import pytest

from chipchain.graph import (
    GraphPersistenceError,
    NetworkXGraphRepository,
)


def test_save_load_round_trip_preserves_graph_and_metadata(
    arm_demo_graph: NetworkXGraphRepository, tmp_path: Path
) -> None:
    """Every node, parallel edge, evidence ID, and metadata value survives JSON."""

    snapshot_path = tmp_path / "graph.json"
    arm_demo_graph.save(snapshot_path)
    restored = NetworkXGraphRepository.load(snapshot_path)

    assert isinstance(restored._graph, nx.MultiDiGraph)
    assert restored.list_nodes() == arm_demo_graph.list_nodes()
    assert restored.list_edges() == arm_demo_graph.list_edges()
    assert restored.metadata == arm_demo_graph.metadata
    assert restored.get_edge("fixture_edge_mmio_write").evidence_ids == [
        "fixture_evidence_mmio_write"
    ]


def test_parallel_edges_survive_save_load(
    arm_demo_graph: NetworkXGraphRepository, tmp_path: Path
) -> None:
    """Both relations on the same source-target pair must survive persistence."""

    snapshot_path = tmp_path / "parallel.json"
    arm_demo_graph.save(snapshot_path)
    restored = NetworkXGraphRepository.load(snapshot_path)

    assert restored._graph.number_of_edges(
        "fixture_parse_command", "fixture_ioctl"
    ) == 2
    assert {
        restored.get_edge("fixture_edge_issues_ioctl").relation.value,
        restored.get_edge("fixture_edge_data_to_ioctl").relation.value,
    } == {"issues", "data_flows_to"}


def test_snapshot_format_is_stable_and_save_is_deterministic(
    arm_demo_graph: NetworkXGraphRepository, tmp_path: Path
) -> None:
    """The public envelope and serialized ordering must be stable."""

    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    arm_demo_graph.save(first)
    arm_demo_graph.save(second)
    payload = json.loads(first.read_text(encoding="utf-8"))

    assert payload["format"] == "chipchain_graph"
    assert payload["format_version"] == 1
    assert set(payload) == {"format", "format_version", "nodes", "edges", "metadata"}
    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "payload",
    [
        "{not-json",
        json.dumps(
            {
                "format": "chipchain_graph",
                "format_version": 1,
                "nodes": [
                    {
                        "id": "bad-node",
                        "kind": "function",
                        "name": "bad-node",
                        "architecture": "invalid-architecture",
                        "layer": "firmware"
                    }
                ],
                "edges": [],
                "metadata": {}
            }
        ),
        json.dumps(
            {
                "format": "wrong-format",
                "format_version": 1,
                "nodes": [],
                "edges": [],
                "metadata": {}
            }
        ),
    ],
)
def test_corrupted_or_invalid_graph_json_is_rejected(
    tmp_path: Path, payload: str
) -> None:
    """Malformed JSON and invalid Pydantic fields must not enter the repository."""

    snapshot_path = tmp_path / "invalid.json"
    snapshot_path.write_text(payload, encoding="utf-8")

    with pytest.raises(GraphPersistenceError):
        NetworkXGraphRepository.load(snapshot_path)


def test_unknown_endpoint_during_load_is_rejected(tmp_path: Path) -> None:
    """Snapshots are revalidated for dangling edges before repository mutation."""

    payload: dict[str, Any] = {
        "format": "chipchain_graph",
        "format_version": 1,
        "nodes": [
            {
                "id": "fixture-source",
                "kind": "function",
                "name": "fixture-source",
                "architecture": "arm",
                "layer": "firmware",
            }
        ],
        "edges": [
            {
                "id": "fixture-dangling-edge",
                "source_id": "fixture-source",
                "target_id": "fixture-missing-target",
                "relation": "calls",
                "architecture": "arm",
            }
        ],
        "metadata": {"fixture": True},
    }
    snapshot_path = tmp_path / "dangling.json"
    snapshot_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(GraphPersistenceError) as exc_info:
        NetworkXGraphRepository.load(snapshot_path)

    assert "unknown endpoint" in str(exc_info.value.__cause__)


def test_missing_snapshot_file_is_reported_as_persistence_error(
    tmp_path: Path,
) -> None:
    """Filesystem failures use the repository's stable public exception type."""

    with pytest.raises(GraphPersistenceError):
        NetworkXGraphRepository.load(tmp_path / "missing.json")
