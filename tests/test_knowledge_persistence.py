"""Tests for stable validated knowledge graph persistence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from chipchain.knowledge import (
    KnowledgePersistenceError,
    NetworkXKnowledgeGraphRepository,
)


def test_knowledge_snapshot_round_trip_preserves_all_catalogs(
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
    tmp_path: Path,
) -> None:
    """Nodes, edges, evidence, scope, and metadata survive JSON reload."""

    path = tmp_path / "knowledge.json"
    synthetic_arm_knowledge_repository.save(path)
    restored = NetworkXKnowledgeGraphRepository.load(path)

    assert restored.architecture == synthetic_arm_knowledge_repository.architecture
    assert restored.sample_ids == synthetic_arm_knowledge_repository.sample_ids
    assert restored.list_nodes() == synthetic_arm_knowledge_repository.list_nodes()
    assert restored.list_edges() == synthetic_arm_knowledge_repository.list_edges()
    assert (
        restored.list_evidence()
        == synthetic_arm_knowledge_repository.list_evidence()
    )
    assert restored.metadata == synthetic_arm_knowledge_repository.metadata


def test_snapshot_format_is_distinct_and_save_is_deterministic(
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
    tmp_path: Path,
) -> None:
    """Knowledge JSON cannot be confused with a behavior graph snapshot."""

    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    synthetic_arm_knowledge_repository.save(first)
    synthetic_arm_knowledge_repository.save(second)
    payload = json.loads(first.read_text(encoding="utf-8"))

    assert payload["format"] == "chipchain_knowledge_graph"
    assert payload["format_version"] == 1
    assert set(payload) == {
        "format",
        "format_version",
        "architecture",
        "sample_ids",
        "nodes",
        "edges",
        "evidence",
        "metadata",
    }
    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.update(format="chipchain_graph"),
        lambda payload: payload["edges"][0].update(target_id="missing-node"),
        lambda payload: payload["edges"][0].update(
            evidence_ids=["missing-evidence"]
        ),
        lambda payload: payload["nodes"][0].update(architecture="risc_v"),
    ],
)
def test_invalid_snapshot_is_rejected(
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
    tmp_path: Path,
    mutation: object,
) -> None:
    """Wrong envelopes and dangling or cross-architecture data fail loading."""

    valid_path = tmp_path / "valid.json"
    invalid_path = tmp_path / "invalid.json"
    synthetic_arm_knowledge_repository.save(valid_path)
    payload = json.loads(valid_path.read_text(encoding="utf-8"))
    mutation(payload)  # type: ignore[operator]
    invalid_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(KnowledgePersistenceError):
        NetworkXKnowledgeGraphRepository.load(invalid_path)


def test_malformed_and_missing_snapshot_are_public_persistence_errors(
    tmp_path: Path,
) -> None:
    """I/O and syntax failures use one stable repository exception."""

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not-json", encoding="utf-8")

    with pytest.raises(KnowledgePersistenceError):
        NetworkXKnowledgeGraphRepository.load(malformed)
    with pytest.raises(KnowledgePersistenceError):
        NetworkXKnowledgeGraphRepository.load(tmp_path / "missing.json")
