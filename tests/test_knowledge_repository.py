"""Tests for the independent NetworkX knowledge graph repository."""

from __future__ import annotations

import networkx as nx
import pytest

from chipchain.knowledge import (
    DuplicateKnowledgeEdgeError,
    DuplicateKnowledgeEvidenceError,
    DuplicateKnowledgeNodeError,
    KnowledgeArchitectureMismatchError,
    KnowledgeEdge,
    KnowledgeEvidenceNotFoundError,
    KnowledgeNode,
    KnowledgeNodeNotFoundError,
    KnowledgeRelationType,
    NetworkXKnowledgeGraphRepository,
)
from chipchain.models import Architecture, Evidence, EvidenceType, Layer


def make_repository() -> NetworkXKnowledgeGraphRepository:
    """Create one empty architecture-scoped fixture repository."""

    return NetworkXKnowledgeGraphRepository(
        architecture=Architecture.ARM,
        sample_ids=["fixture-sample"],
        metadata={"fixture": True},
    )


def make_node(node_id: str, *, evidence_ids: list[str] | None = None) -> KnowledgeNode:
    """Create a small ARM component knowledge node."""

    return KnowledgeNode(
        id=node_id,
        kind="component",
        label=node_id,
        architecture="arm",
        layer=Layer.DRIVER,
        evidence_ids=evidence_ids or [],
        metadata={"fixture": True},
    )


def make_evidence(evidence_id: str = "fixture-evidence") -> Evidence:
    """Create one owned evidence record."""

    return Evidence(
        id=evidence_id,
        type=EvidenceType.SOURCE_REFERENCE,
        source="fixture-source",
        confidence=1.0,
        verified=True,
        metadata={"fixture": True},
    )


def make_edge(
    edge_id: str = "fixture-edge",
    *,
    source_id: str = "fixture-source",
    target_id: str = "fixture-target",
    evidence_ids: list[str] | None = None,
) -> KnowledgeEdge:
    """Create one small semantic knowledge edge."""

    return KnowledgeEdge(
        id=edge_id,
        source_id=source_id,
        target_id=target_id,
        relation=KnowledgeRelationType.AFFECTS_COMPONENT,
        architecture=Architecture.ARM,
        evidence_ids=evidence_ids or [],
        metadata={"fixture": True},
    )


def test_repository_is_independent_multidigraph_with_evidence_catalog(
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
) -> None:
    """Knowledge storage uses MultiDiGraph and retains standalone evidence."""

    assert isinstance(synthetic_arm_knowledge_repository._graph, nx.MultiDiGraph)
    assert len(synthetic_arm_knowledge_repository.list_evidence()) == 2
    assert not hasattr(synthetic_arm_knowledge_repository, "find_paths")


def test_add_get_list_and_adjacency_are_deterministic() -> None:
    """Basic entity operations preserve direction and stable ordering."""

    repository = make_repository()
    repository.add_evidence(make_evidence())
    repository.add_node(make_node("fixture-target"))
    repository.add_node(make_node("fixture-source", evidence_ids=["fixture-evidence"]))
    repository.add_edge(
        make_edge(evidence_ids=["fixture-evidence"])
    )

    assert repository.get_node("fixture-source").evidence_ids == [
        "fixture-evidence"
    ]
    assert repository.get_edge("fixture-edge").evidence_ids == [
        "fixture-evidence"
    ]
    assert repository.get_evidence("fixture-evidence").verified is True
    assert [node.id for node in repository.list_nodes()] == [
        "fixture-source",
        "fixture-target",
    ]
    assert [node.id for node in repository.successors("fixture-source")] == [
        "fixture-target"
    ]
    assert [node.id for node in repository.predecessors("fixture-target")] == [
        "fixture-source"
    ]


def test_duplicate_node_edge_and_evidence_ids_are_rejected() -> None:
    """No repository insertion may silently overwrite an existing entity."""

    repository = make_repository()
    evidence = make_evidence()
    repository.add_evidence(evidence)
    repository.add_node(make_node("fixture-source"))
    repository.add_node(make_node("fixture-target"))
    edge = make_edge()
    repository.add_edge(edge)

    with pytest.raises(DuplicateKnowledgeEvidenceError):
        repository.add_evidence(evidence)
    with pytest.raises(DuplicateKnowledgeNodeError):
        repository.add_node(make_node("fixture-source"))
    with pytest.raises(DuplicateKnowledgeEdgeError):
        repository.add_edge(edge)


def test_parallel_semantic_relations_are_preserved() -> None:
    """MultiDiGraph retains two knowledge relations on the same entity pair."""

    repository = make_repository()
    repository.add_node(make_node("fixture-source"))
    repository.add_node(make_node("fixture-target"))
    repository.add_edge(make_edge("fixture-affects"))
    repository.add_edge(
        KnowledgeEdge(
            id="fixture-targets",
            source_id="fixture-source",
            target_id="fixture-target",
            relation="targets_resource",
            architecture="arm",
            metadata={"fixture": True},
        )
    )

    assert repository._graph.number_of_edges(
        "fixture-source", "fixture-target"
    ) == 2
    assert {edge.relation for edge in repository.list_edges()} == {
        KnowledgeRelationType.AFFECTS_COMPONENT,
        KnowledgeRelationType.TARGETS_RESOURCE,
    }


def test_dangling_endpoints_and_evidence_are_rejected() -> None:
    """Nodes and edges cannot reference absent graph or evidence entities."""

    repository = make_repository()
    with pytest.raises(KnowledgeEvidenceNotFoundError):
        repository.add_node(
            make_node("fixture-source", evidence_ids=["fixture-missing"])
        )

    repository.add_node(make_node("fixture-source"))
    with pytest.raises(KnowledgeNodeNotFoundError, match="target node"):
        repository.add_edge(make_edge(target_id="fixture-missing"))

    repository.add_node(make_node("fixture-target"))
    with pytest.raises(KnowledgeEvidenceNotFoundError):
        repository.add_edge(make_edge(evidence_ids=["fixture-missing"]))


def test_repository_rejects_cross_architecture_entities() -> None:
    """An ARM repository cannot accept a concrete RISC-V knowledge node."""

    repository = make_repository()
    riscv_node = KnowledgeNode(
        id="fixture-riscv",
        kind="component",
        label="fixture-riscv",
        architecture="risc_v",
        layer="driver",
    )

    with pytest.raises(KnowledgeArchitectureMismatchError):
        repository.add_node(riscv_node)


def test_relation_and_kind_filters_use_knowledge_enums(
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
) -> None:
    """Repository filters remain separate from behavior graph enums."""

    cwe_nodes = synthetic_arm_knowledge_repository.list_nodes(kind="cwe")
    cwe_edges = synthetic_arm_knowledge_repository.list_edges(relation="has_cwe")

    assert [node.id for node in cwe_nodes] == ["cwe:CWE-284"]
    assert len(cwe_edges) == 1
    assert cwe_edges[0].relation is KnowledgeRelationType.HAS_CWE
