"""Strict positive and tampering tests for Phase 9A behavior verification."""

from __future__ import annotations

import pytest

from chipchain.models import (
    Architecture,
    BehaviorEdge,
    BehaviorNode,
    Evidence,
    EvidenceType,
    Layer,
    NodeKind,
    RelationType,
)
from chipchain.verification import BehaviorEdgeVerifier, EvidenceCatalog, VerificationStatus


def _function(node_id: str, address: str, *, architecture=Architecture.ARM) -> BehaviorNode:
    return BehaviorNode(
        id=node_id,
        kind=NodeKind.FUNCTION,
        name=node_id,
        architecture=architecture,
        layer=Layer.DRIVER,
        address=address,
    )


def _calls(*, caller="0x1000", callee="0x2000", verified=True, evidence_type=EvidenceType.STATIC_ANALYSIS):
    source = _function("caller", "0x1000")
    target = _function("callee", "0x2000")
    edge = BehaviorEdge(
        id="calls-edge",
        source_id=source.id,
        target_id=target.id,
        relation=RelationType.CALLS,
        architecture=Architecture.ARM,
        evidence_ids=["calls-evidence"],
        metadata={"observation": "call_xref", "resolved": True},
    )
    evidence = Evidence(
        id="calls-evidence",
        type=evidence_type,
        source="fixture-analyzer",
        address="0x1004",
        confidence=1.0,
        verified=verified,
        metadata={
            "observation": "call_xref",
            "caller_address": caller,
            "callee_address": callee,
            "resolved": True,
        },
    )
    return source, target, edge, evidence


def _mmio(*, relation=RelationType.MMIO_WRITE, observation="mmio_write", target_address="0x40000000", region="reg-a", verified=True, evidence_type=EvidenceType.STATIC_ANALYSIS):
    source = _function("driver", "0x1000")
    target = BehaviorNode(
        id="register",
        kind=NodeKind.REGISTER,
        name="REG",
        architecture=Architecture.ARM,
        layer=Layer.HARDWARE,
        address="0x40000000",
        metadata={
            "memory_map_id": "map-a",
            "memory_map_region": "reg-a",
            "region_start": "0x40000000",
            "region_end": "0x40000000",
        },
    )
    edge = BehaviorEdge(
        id="mmio-edge",
        source_id=source.id,
        target_id=target.id,
        relation=relation,
        architecture=Architecture.ARM,
        evidence_ids=["mmio-evidence"],
        metadata={
            "observation": relation.value,
            "resolved_target_address": "0x40000000",
            "memory_map_id": "map-a",
            "memory_map_region": "reg-a",
            "instruction_address": "0x1008",
        },
    )
    evidence = Evidence(
        id="mmio-evidence",
        type=evidence_type,
        source="fixture-analyzer",
        address="0x1008",
        confidence=1.0,
        verified=verified,
        metadata={
            "observation": observation,
            "resolved_target_address": target_address,
            "memory_map_id": "map-a",
            "memory_map_region": region,
            "resolved": True,
        },
    )
    return source, target, edge, evidence


def test_calls_static_evidence_verifies_and_sources_remain_unchanged():
    source, target, edge, evidence = _calls()
    before = [item.model_dump_json() for item in (source, target, edge, evidence)]
    result = BehaviorEdgeVerifier().verify(edge, source, target, EvidenceCatalog([evidence]))
    assert result.status is VerificationStatus.VERIFIED
    assert [item.model_dump_json() for item in (source, target, edge, evidence)] == before


@pytest.mark.parametrize("field,value", [("caller_address", "0x1004"), ("callee_address", "0x2004")])
def test_tampered_calls_addresses_are_rejected(field: str, value: str):
    source, target, edge, evidence = _calls()
    data = evidence.model_dump(mode="json")
    data["metadata"][field] = value
    result = BehaviorEdgeVerifier().verify(edge, source, target, EvidenceCatalog([Evidence.model_validate(data)]))
    assert result.status is VerificationStatus.REJECTED


def test_mmio_static_evidence_verifies():
    source, target, edge, evidence = _mmio()
    result = BehaviorEdgeVerifier().verify(edge, source, target, EvidenceCatalog([evidence]))
    assert result.status is VerificationStatus.VERIFIED


@pytest.mark.parametrize(
    "changes",
    [
        {"resolved_target_address": "0x40000004"},
        {"memory_map_region": "reg-b"},
        {"observation": "mmio_read"},
    ],
)
def test_tampered_mmio_evidence_is_rejected(changes: dict[str, object]):
    source, target, edge, evidence = _mmio()
    data = evidence.model_dump(mode="json")
    data["metadata"].update(changes)
    result = BehaviorEdgeVerifier().verify(edge, source, target, EvidenceCatalog([Evidence.model_validate(data)]))
    assert result.status is VerificationStatus.REJECTED


def test_mmio_read_edge_with_write_evidence_is_rejected():
    source, target, edge, evidence = _mmio(
        relation=RelationType.MMIO_READ,
        observation="mmio_write",
    )
    result = BehaviorEdgeVerifier().verify(edge, source, target, EvidenceCatalog([evidence]))
    assert result.status is VerificationStatus.REJECTED


def test_mmio_instruction_address_mismatch_is_rejected():
    source, target, edge, evidence = _mmio()
    data = evidence.model_dump(mode="json")
    data["address"] = "0x100c"
    result = BehaviorEdgeVerifier().verify(
        edge, source, target, EvidenceCatalog([Evidence.model_validate(data)])
    )
    assert result.status is VerificationStatus.REJECTED


def test_mmio_edge_memory_map_region_mismatch_is_rejected():
    source, target, edge, evidence = _mmio()
    data = edge.model_dump(mode="json")
    data["metadata"]["memory_map_region"] = "reg-b"
    result = BehaviorEdgeVerifier().verify(
        BehaviorEdge.model_validate(data), source, target, EvidenceCatalog([evidence])
    )
    assert result.status is VerificationStatus.REJECTED


@pytest.mark.parametrize(
    "catalog_factory",
    [
        lambda evidence: EvidenceCatalog([]),
        lambda evidence: EvidenceCatalog([evidence.model_copy(update={"verified": False})]),
        lambda evidence: EvidenceCatalog([evidence.model_copy(update={"type": EvidenceType.LLM_SEMANTIC})]),
    ],
)
def test_missing_unverified_or_llm_only_evidence_is_unknown(catalog_factory):
    source, target, edge, evidence = _calls()
    result = BehaviorEdgeVerifier().verify(edge, source, target, catalog_factory(evidence))
    assert result.status is VerificationStatus.UNKNOWN


def test_cross_architecture_behavior_context_is_rejected():
    source, target, edge, evidence = _calls()
    wrong_target = _function("callee", "0x2000", architecture=Architecture.RISC_V)
    result = BehaviorEdgeVerifier().verify(edge, source, wrong_target, EvidenceCatalog([evidence]))
    assert result.status is VerificationStatus.REJECTED


def test_unsupported_behavior_relation_is_unknown():
    source, target, edge, evidence = _calls()
    data = edge.model_dump(mode="json")
    data["relation"] = RelationType.DATA_FLOWS_TO.value
    edge = BehaviorEdge.model_validate(data)
    result = BehaviorEdgeVerifier().verify(edge, source, target, EvidenceCatalog([evidence]))
    assert result.status is VerificationStatus.UNKNOWN


def test_missing_calls_comparison_field_is_unknown_not_rejected():
    source, target, edge, evidence = _calls()
    source = source.model_copy(update={"address": None})
    result = BehaviorEdgeVerifier().verify(edge, source, target, EvidenceCatalog([evidence]))
    assert result.status is VerificationStatus.UNKNOWN


def test_missing_mmio_hardware_map_field_is_unknown_not_rejected():
    source, target, edge, evidence = _mmio()
    data = target.model_dump(mode="json")
    del data["metadata"]["memory_map_region"]
    result = BehaviorEdgeVerifier().verify(
        edge,
        source,
        BehaviorNode.model_validate(data),
        EvidenceCatalog([evidence]),
    )
    assert result.status is VerificationStatus.UNKNOWN
