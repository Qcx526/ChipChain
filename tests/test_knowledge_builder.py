"""Tests for deterministic VulnerabilitySample-to-knowledge conversion."""

from __future__ import annotations

from chipchain.knowledge import (
    KnowledgeGraphBundle,
    KnowledgeNodeKind,
    KnowledgeRelationType,
    VulnerabilityKnowledgeBuilder,
    hardware_resource_match_keys,
)
from chipchain.models import (
    Architecture,
    BehaviorNode,
    Component,
    Layer,
    NodeKind,
    SampleType,
    VulnerabilitySample,
)


def test_builder_maps_every_phase5_relation(
    synthetic_arm_knowledge_bundle: KnowledgeGraphBundle,
) -> None:
    """The full owned fixture exercises every Phase 5 semantic relation."""

    relations = {edge.relation for edge in synthetic_arm_knowledge_bundle.edges}
    node_kinds = {node.kind for node in synthetic_arm_knowledge_bundle.nodes}

    assert relations == set(KnowledgeRelationType)
    assert node_kinds == set(KnowledgeNodeKind)
    assert len(synthetic_arm_knowledge_bundle.nodes) == 12
    assert len(synthetic_arm_knowledge_bundle.edges) == 11


def test_builder_is_deterministic_and_does_not_mutate_source(
    synthetic_arm_knowledge_sample: VulnerabilitySample,
) -> None:
    """Stable IDs and namespaced copies must not alter the domain sample."""

    builder = VulnerabilityKnowledgeBuilder()
    before = synthetic_arm_knowledge_sample.model_dump_json()

    first = builder.build(synthetic_arm_knowledge_sample)
    second = builder.build(synthetic_arm_knowledge_sample)
    node_ids = {node.id for node in first.nodes}

    assert first == second
    assert "vulnerability:FIXTURE-ARM-KG-001" in node_ids
    assert (
        "component:arm:FIXTURE-ARM-KG-001:fixture-driver-component"
        in node_ids
    )
    assert (
        "hardware-resource:arm:FIXTURE-ARM-KG-001:fixture-mmio-register"
        in node_ids
    )
    assert all(
        edge.metadata["derived_from_sample"] == "FIXTURE-ARM-KG-001"
        for edge in first.edges
    )
    assert synthetic_arm_knowledge_sample.model_dump_json() == before
    assert [item.id for item in synthetic_arm_knowledge_sample.evidence] == [
        "local-static-1",
        "local-source-1",
    ]


def test_builder_namespaces_evidence_across_samples_and_deduplicates_taxonomy(
    synthetic_arm_knowledge_sample: VulnerabilitySample,
) -> None:
    """Local evidence IDs cannot collide and global taxonomy nodes remain singletons."""

    data = synthetic_arm_knowledge_sample.model_dump(mode="json")
    data["id"] = "FIXTURE-ARM-KG-002"
    second_sample = VulnerabilitySample.model_validate(data)
    bundle = VulnerabilityKnowledgeBuilder().build_many(
        [synthetic_arm_knowledge_sample, second_sample]
    )

    evidence_ids = {item.id for item in bundle.evidence}
    cwe_nodes = [node for node in bundle.nodes if node.kind is KnowledgeNodeKind.CWE]
    capec_nodes = [
        node for node in bundle.nodes if node.kind is KnowledgeNodeKind.CAPEC
    ]
    vulnerability_nodes = [
        node
        for node in bundle.nodes
        if node.kind is KnowledgeNodeKind.VULNERABILITY
    ]

    assert "sample:FIXTURE-ARM-KG-001:evidence:local-static-1" in evidence_ids
    assert "sample:FIXTURE-ARM-KG-002:evidence:local-static-1" in evidence_ids
    assert len(evidence_ids) == 4
    assert len(cwe_nodes) == 1
    assert len(capec_nodes) == 1
    assert len(vulnerability_nodes) == 2


def test_vulnerability_metadata_preserves_sample_provenance(
    synthetic_arm_knowledge_bundle: KnowledgeGraphBundle,
) -> None:
    """Sample type, source, references, and verification survive conversion."""

    vulnerability = next(
        node
        for node in synthetic_arm_knowledge_bundle.nodes
        if node.kind is KnowledgeNodeKind.VULNERABILITY
    )

    assert vulnerability.metadata["sample_type"] == "fixture"
    assert vulnerability.metadata["source"] == "chipchain-owned-synthetic-fixture"
    assert vulnerability.metadata["verified"] is False
    assert vulnerability.metadata["references"] == [
        "tests/fixtures/knowledge/synthetic_arm_vulnerability.json"
    ]


def test_trigger_and_precondition_are_first_class_nodes(
    synthetic_arm_knowledge_bundle: KnowledgeGraphBundle,
) -> None:
    """Structured conditions remain entities rather than opaque edge metadata."""

    kinds = {node.kind for node in synthetic_arm_knowledge_bundle.nodes}

    assert KnowledgeNodeKind.TRIGGER in kinds
    assert KnowledgeNodeKind.PRECONDITION in kinds


def test_builder_does_not_invent_evidence_for_empty_sample() -> None:
    """Relations may honestly carry no evidence when the source has none."""

    sample = VulnerabilitySample(
        id="FIXTURE-EMPTY-EVIDENCE",
        sample_type=SampleType.FIXTURE,
        architecture=Architecture.ARM,
        layer=Layer.DRIVER,
        component=Component(
            id="fixture-component",
            name="Fixture Component",
            kind="driver",
            architecture=Architecture.ARM,
            layer=Layer.DRIVER,
            metadata={"fixture": True},
        ),
        metadata={"fixture": True},
    )

    bundle = VulnerabilityKnowledgeBuilder().build(sample)

    assert bundle.evidence == []
    assert all(edge.evidence_ids == [] for edge in bundle.edges)


def test_hardware_match_keys_equal_phase4b_behavior_anchor(
    synthetic_arm_knowledge_bundle: KnowledgeGraphBundle,
) -> None:
    """Both separate graphs independently compute the same exact anchor keys."""

    knowledge_resource = next(
        node
        for node in synthetic_arm_knowledge_bundle.nodes
        if node.kind is KnowledgeNodeKind.HARDWARE_RESOURCE
    )
    phase4b_behavior_node = BehaviorNode(
        id=(
            "synthetic-arm-mmio:memory-map:synthetic-arm-mmio-map:"
            "region:fixture-mmio-register"
        ),
        kind=NodeKind.REGISTER,
        name="FIXTURE_MMIO_REGISTER",
        architecture=Architecture.ARM,
        layer=Layer.HARDWARE,
        address="0x40000000",
        metadata={
            "analyzer": "angr_analyzer",
            "memory_map_id": "synthetic-arm-mmio-map",
            "memory_map_region": "fixture-mmio-register",
            "fixture": True,
        },
    )
    behavior_keys = hardware_resource_match_keys(
        phase4b_behavior_node.architecture,
        address=phase4b_behavior_node.address,
        metadata=phase4b_behavior_node.metadata,
    )

    assert knowledge_resource.id != phase4b_behavior_node.id
    assert knowledge_resource.match_keys == behavior_keys
    assert knowledge_resource.match_keys == [
        "arch:arm:address:0x40000000",
        (
            "arch:arm:mmio-map:synthetic-arm-mmio-map:"
            "region:fixture-mmio-register"
        ),
    ]
    assert not any(
        edge.source_id == phase4b_behavior_node.id
        or edge.target_id == phase4b_behavior_node.id
        for edge in synthetic_arm_knowledge_bundle.edges
    )


def test_hardware_match_keys_do_not_guess_from_symbolic_address_or_name() -> None:
    """Unsupported address text and labels never become fuzzy entity anchors."""

    assert hardware_resource_match_keys(
        Architecture.ARM,
        address="FIXTURE_REGISTER_SYMBOL",
        metadata={"name": "FIXTURE_MMIO_REGISTER"},
    ) == []
