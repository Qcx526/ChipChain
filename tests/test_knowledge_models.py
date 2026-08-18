"""Tests for strict independent vulnerability knowledge graph models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from chipchain.knowledge import (
    KnowledgeEdge,
    KnowledgeGraphBundle,
    KnowledgeNode,
    KnowledgeNodeKind,
    KnowledgeRelationType,
)
from chipchain.models import Architecture, Evidence, EvidenceType, Layer


def make_node(node_id: str = "fixture-node") -> KnowledgeNode:
    """Create one small architecture-specific knowledge node."""

    return KnowledgeNode(
        id=node_id,
        kind=KnowledgeNodeKind.COMPONENT,
        label=node_id,
        architecture=Architecture.ARM,
        layer=Layer.DRIVER,
        metadata={"fixture": True},
    )


def make_evidence(evidence_id: str = "fixture-evidence") -> Evidence:
    """Create one owned synthetic evidence record."""

    return Evidence(
        id=evidence_id,
        type=EvidenceType.SOURCE_REFERENCE,
        source="fixture-source",
        confidence=1.0,
        verified=True,
        metadata={"fixture": True},
    )


def test_only_cwe_and_capec_may_be_global() -> None:
    """Taxonomy nodes are global while concrete vulnerability entities are scoped."""

    cwe = KnowledgeNode(
        id="cwe:CWE-284",
        kind="cwe",
        label="CWE-284",
        architecture=None,
    )
    capec = KnowledgeNode(
        id="capec:FIXTURE-CAPEC",
        kind="capec",
        label="FIXTURE-CAPEC",
        architecture=None,
    )

    assert cwe.architecture is None
    assert capec.architecture is None
    with pytest.raises(ValidationError, match="only CWE and CAPEC"):
        KnowledgeNode(
            id="component:unscoped",
            kind="component",
            label="unscoped",
            architecture=None,
        )
    with pytest.raises(ValidationError, match="must be global"):
        KnowledgeNode(
            id="cwe:scoped",
            kind="cwe",
            label="CWE-scoped",
            architecture="arm",
        )


def test_knowledge_relations_do_not_reuse_behavior_edge_vocabulary() -> None:
    """CALLS and MMIO_WRITE belong only to the behavior graph contract."""

    values = {item.value for item in KnowledgeRelationType}

    assert "calls" not in values
    assert "mmio_write" not in values
    assert "has_trigger" in values
    assert "targets_resource" in values


def test_knowledge_edge_rejects_invalid_relation_and_duplicate_evidence() -> None:
    """Edge fields remain strict even before bundle-level endpoint validation."""

    with pytest.raises(ValidationError):
        KnowledgeEdge(
            id="fixture-invalid-relation",
            source_id="fixture-source",
            target_id="fixture-target",
            relation="calls",
            architecture="arm",
        )
    with pytest.raises(ValidationError, match="evidence IDs must be unique"):
        KnowledgeEdge(
            id="fixture-duplicate-evidence",
            source_id="fixture-source",
            target_id="fixture-target",
            relation="affects_component",
            architecture="arm",
            evidence_ids=["fixture-evidence", "fixture-evidence"],
        )


def test_bundle_json_round_trip_preserves_models(
    synthetic_arm_knowledge_bundle: KnowledgeGraphBundle,
) -> None:
    """Bundle JSON rehydrates through Pydantic without losing evidence."""

    restored = KnowledgeGraphBundle.model_validate_json(
        synthetic_arm_knowledge_bundle.model_dump_json()
    )

    assert restored == synthetic_arm_knowledge_bundle


def test_bundle_rejects_duplicate_and_dangling_entities() -> None:
    """Bundle-level IDs and edge endpoints are strict invariants."""

    source = make_node("fixture-source")
    with pytest.raises(ValidationError, match="node IDs must be unique"):
        KnowledgeGraphBundle(
            architecture="arm",
            sample_ids=["fixture-sample"],
            nodes=[source, source],
        )

    dangling = KnowledgeEdge(
        id="fixture-edge",
        source_id=source.id,
        target_id="fixture-missing",
        relation="affects_component",
        architecture="arm",
    )
    with pytest.raises(ValidationError, match="unknown endpoint"):
        KnowledgeGraphBundle(
            architecture="arm",
            sample_ids=["fixture-sample"],
            nodes=[source],
            edges=[dangling],
        )


def test_bundle_rejects_unknown_evidence_and_architecture_leakage() -> None:
    """Evidence references and architecture-specific nodes cannot dangle or leak."""

    bad_evidence_node = make_node().model_copy(
        update={"evidence_ids": ["fixture-missing-evidence"]}
    )
    with pytest.raises(ValidationError, match="unknown evidence"):
        KnowledgeGraphBundle(
            architecture="arm",
            sample_ids=["fixture-sample"],
            nodes=[bad_evidence_node],
        )

    riscv_node = make_node().model_copy(
        update={"id": "fixture-riscv", "architecture": Architecture.RISC_V}
    )
    with pytest.raises(ValidationError, match="does not match bundle"):
        KnowledgeGraphBundle(
            architecture="arm",
            sample_ids=["fixture-sample"],
            nodes=[riscv_node],
        )


def test_bundle_rejects_arm_to_riscv_knowledge_edge() -> None:
    """An ARM semantic relation can never enter a concrete RISC-V entity."""

    arm_source = make_node("fixture-arm")
    riscv_target = make_node("fixture-riscv").model_copy(
        update={"architecture": Architecture.RISC_V}
    )
    cross_edge = KnowledgeEdge(
        id="fixture-cross-architecture",
        source_id=arm_source.id,
        target_id=riscv_target.id,
        relation="affects_component",
        architecture="arm",
    )

    with pytest.raises(ValidationError, match="does not match bundle"):
        KnowledgeGraphBundle(
            architecture="arm",
            sample_ids=["fixture-sample"],
            nodes=[arm_source, riscv_target],
            edges=[cross_edge],
        )


def test_bundle_rejects_duplicate_evidence_ids() -> None:
    """Evidence catalog IDs are globally unique within a bundle."""

    evidence = make_evidence()
    with pytest.raises(ValidationError, match="evidence IDs must be unique"):
        KnowledgeGraphBundle(
            architecture="arm",
            sample_ids=["fixture-sample"],
            evidence=[evidence, evidence],
        )


def test_arm_edge_may_target_global_cwe_but_remains_arm() -> None:
    """A link to a global taxonomy node retains the vulnerability architecture."""

    vulnerability = KnowledgeNode(
        id="vulnerability:fixture",
        kind="vulnerability",
        label="fixture",
        architecture="arm",
        layer="driver",
    )
    cwe = KnowledgeNode(
        id="cwe:CWE-284",
        kind="cwe",
        label="CWE-284",
        architecture=None,
    )
    edge = KnowledgeEdge(
        id="fixture-has-cwe",
        source_id=vulnerability.id,
        target_id=cwe.id,
        relation="has_cwe",
        architecture="arm",
    )

    bundle = KnowledgeGraphBundle(
        architecture="arm",
        sample_ids=["fixture"],
        nodes=[vulnerability, cwe],
        edges=[edge],
    )

    assert bundle.edges[0].architecture is Architecture.ARM
