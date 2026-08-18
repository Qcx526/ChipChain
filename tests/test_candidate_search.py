"""Tests for Phase 6B deterministic cross-graph candidate search."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from chipchain.candidate import (
    CrossGraphCandidate,
    CrossGraphCandidateSearcher,
    EntityLink,
    InvalidKnowledgeContextError,
)
from chipchain.graph import NetworkXGraphRepository
from chipchain.knowledge import (
    KnowledgeEdge,
    KnowledgeGraphBundle,
    KnowledgeNode,
    NetworkXKnowledgeGraphRepository,
    VulnerabilityKnowledgeBuilder,
)
from chipchain.models import (
    Architecture,
    BehaviorEdge,
    BehaviorNode,
    Layer,
    NodeKind,
    RelationType,
    VulnerabilitySample,
)

START_ID = "fixture-driver-start"
ANCHOR_ID = "fixture-behavior-register"
BEHAVIOR_EDGE_ID = "fixture-mmio-write"


def make_behavior_repository(
    *, relation: RelationType = RelationType.MMIO_WRITE,
) -> NetworkXGraphRepository:
    """Create one reachable driver-to-hardware behavior path."""

    repository = NetworkXGraphRepository(metadata={"fixture": True})
    repository.add_node(
        BehaviorNode(
            id=START_ID,
            kind=NodeKind.FUNCTION,
            name="fixture_driver_start",
            architecture=Architecture.ARM,
            layer=Layer.DRIVER,
            metadata={"fixture": True},
        )
    )
    repository.add_node(
        BehaviorNode(
            id=ANCHOR_ID,
            kind=NodeKind.REGISTER,
            name="FIXTURE_MMIO_REGISTER",
            architecture=Architecture.ARM,
            layer=Layer.HARDWARE,
            address="0x40000000",
            metadata={
                "memory_map_id": "synthetic-arm-mmio-map",
                "memory_map_region": "fixture-mmio-register",
                "fixture": True,
            },
        )
    )
    repository.add_edge(
        BehaviorEdge(
            id=BEHAVIOR_EDGE_ID,
            source_id=START_ID,
            target_id=ANCHOR_ID,
            relation=relation,
            architecture=Architecture.ARM,
            evidence_ids=["fixture-behavior-evidence"],
            metadata={"fixture": True},
        )
    )
    return repository


def search_fixture(
    knowledge: NetworkXKnowledgeGraphRepository,
    *,
    behavior: NetworkXGraphRepository | None = None,
    start_node_id: str = START_ID,
    top_n: int | None = None,
) -> list[CrossGraphCandidate]:
    """Run the standard one-hop ARM fixture query."""

    return CrossGraphCandidateSearcher().search(
        behavior or make_behavior_repository(),
        knowledge,
        architecture=Architecture.ARM,
        start_node_id=start_node_id,
        max_hops=2,
        top_n=top_n,
    )


def test_search_reaches_anchor_and_collects_full_direct_context(
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
) -> None:
    """A reachable exact anchor retains trigger, conditions, taxonomy, and impact."""

    candidates = search_fixture(synthetic_arm_knowledge_repository)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.behavior_path.node_ids == [START_ID, ANCHOR_ID]
    assert candidate.behavior_path.edge_ids == [BEHAVIOR_EDGE_ID]
    assert candidate.behavior_layers == [Layer.DRIVER, Layer.HARDWARE]
    assert candidate.knowledge_vulnerability_id == (
        "vulnerability:FIXTURE-ARM-KG-001"
    )
    assert len(candidate.component_node_ids) == 1
    assert len(candidate.trigger_node_ids) == 1
    assert len(candidate.precondition_node_ids) == 1
    assert candidate.cwe_node_ids == ["cwe:CWE-284"]
    assert candidate.capec_node_ids == [
        "capec:FIXTURE-CAPEC-MMIO-ACCESS"
    ]
    assert len(candidate.behavior_node_ids) == 1
    assert len(candidate.interface_node_ids) == 1
    assert len(candidate.hardware_resource_node_ids) == 1
    assert len(candidate.security_mechanism_node_ids) == 1
    assert len(candidate.impact_node_ids) == 1
    assert len(candidate.root_cause_node_ids) == 1
    assert len(candidate.knowledge_edge_ids) == 11


def test_candidate_aggregates_existing_evidence_and_preserves_missing_state(
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
) -> None:
    """Evidence IDs are referenced once while evidence-free KG edges remain visible."""

    candidate = search_fixture(synthetic_arm_knowledge_repository)[0]

    assert candidate.behavior_evidence_ids == ["fixture-behavior-evidence"]
    assert candidate.knowledge_evidence_ids == [
        "sample:FIXTURE-ARM-KG-001:evidence:local-source-1",
        "sample:FIXTURE-ARM-KG-001:evidence:local-static-1",
    ]
    assert candidate.knowledge_evidence_count == 2
    assert candidate.missing_knowledge_evidence is True
    assert candidate.metadata["status"] == "unverified_correlation"


def test_candidate_model_is_strict_deterministic_and_round_trips(
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
) -> None:
    """Candidate identity, architecture, lists, and JSON contract are validated."""

    first = search_fixture(synthetic_arm_knowledge_repository)[0]
    second = search_fixture(synthetic_arm_knowledge_repository)[0]
    restored = CrossGraphCandidate.model_validate_json(first.model_dump_json())

    assert first == second == restored
    assert first.id.startswith("cross-graph-candidate:arm:")

    duplicated = first.model_dump(mode="json")
    duplicated["knowledge_edge_ids"] = [
        first.knowledge_edge_ids[0],
        first.knowledge_edge_ids[0],
    ]
    with pytest.raises(ValidationError, match="ID lists must be unique"):
        CrossGraphCandidate.model_validate(duplicated)

    wrong_architecture = first.model_dump(mode="json")
    wrong_architecture["behavior_path"]["architecture"] = "risc_v"
    with pytest.raises(ValidationError, match="path architecture"):
        CrossGraphCandidate.model_validate(wrong_architecture)

    wrong_link_architecture = first.model_dump(mode="json")
    wrong_link_architecture["entity_link"] = EntityLink.create(
        architecture=Architecture.RISC_V,
        behavior_node_id=first.entity_link.behavior_node_id,
        knowledge_node_id=first.entity_link.knowledge_node_id,
        behavior_node_kind=first.entity_link.behavior_node_kind,
        knowledge_node_kind=first.entity_link.knowledge_node_kind,
        match_keys=["arch:risc_v:address:0x40000000"],
    ).model_dump(mode="json")
    with pytest.raises(ValidationError, match="EntityLink architecture"):
        CrossGraphCandidate.model_validate(wrong_link_architecture)

    wrong_id = first.model_dump(mode="json")
    wrong_id["id"] = "cross-graph-candidate:arm:wrong"
    with pytest.raises(ValidationError, match="deterministic identity"):
        CrossGraphCandidate.model_validate(wrong_id)


def test_candidate_model_rejects_firmware_only_path(
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
) -> None:
    """A same-layer path cannot be labeled a Phase 6 cross-layer candidate."""

    candidate = search_fixture(synthetic_arm_knowledge_repository)[0]
    data = candidate.model_dump(mode="json")
    data["behavior_layers"] = ["firmware", "firmware"]

    with pytest.raises(ValidationError, match="cross at least two layers"):
        CrossGraphCandidate.model_validate(data)

    no_hardware = candidate.model_dump(mode="json")
    no_hardware["behavior_layers"] = ["driver", "interface"]
    with pytest.raises(ValidationError, match="include hardware"):
        CrossGraphCandidate.model_validate(no_hardware)


def test_unreachable_anchor_and_disallowed_behavior_relation_return_no_candidate(
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
) -> None:
    """Search requires reachability through the allowed program-relation set."""

    behavior = make_behavior_repository()
    behavior.add_node(
        BehaviorNode(
            id="fixture-disconnected-start",
            kind=NodeKind.FUNCTION,
            name="fixture_disconnected_start",
            architecture="arm",
            layer="driver",
            metadata={"fixture": True},
        )
    )
    unreachable = search_fixture(
        synthetic_arm_knowledge_repository,
        behavior=behavior,
        start_node_id="fixture-disconnected-start",
    )
    disallowed = search_fixture(
        synthetic_arm_knowledge_repository,
        behavior=make_behavior_repository(relation=RelationType.EXPLOITS),
    )

    assert unreachable == []
    assert disallowed == []


def test_resource_without_incoming_targets_relation_has_no_candidate() -> None:
    """An exact resource link alone does not imply a vulnerability context."""

    resource = KnowledgeNode(
        id="fixture-resource",
        kind="hardware_resource",
        label="FIXTURE_MMIO_REGISTER",
        architecture="arm",
        layer="hardware",
        match_keys=["arch:arm:address:0x40000000"],
        metadata={"fixture": True},
    )
    knowledge = NetworkXKnowledgeGraphRepository.from_bundle(
        KnowledgeGraphBundle(
            architecture="arm",
            sample_ids=["fixture-sample"],
            nodes=[resource],
            metadata={"fixture": True},
        )
    )

    assert search_fixture(knowledge) == []


def test_targets_resource_source_must_be_vulnerability() -> None:
    """Malformed semantic direction is rejected instead of being inverted."""

    component = KnowledgeNode(
        id="fixture-component",
        kind="component",
        label="Fixture Component",
        architecture="arm",
        layer="driver",
        metadata={"fixture": True},
    )
    resource = KnowledgeNode(
        id="fixture-resource",
        kind="hardware_resource",
        label="Fixture Resource",
        architecture="arm",
        layer="hardware",
        match_keys=["arch:arm:address:0x40000000"],
        metadata={"fixture": True},
    )
    edge = KnowledgeEdge(
        id="fixture-invalid-target-edge",
        source_id=component.id,
        target_id=resource.id,
        relation="targets_resource",
        architecture="arm",
        metadata={"fixture": True},
    )
    knowledge = NetworkXKnowledgeGraphRepository.from_bundle(
        KnowledgeGraphBundle(
            architecture="arm",
            sample_ids=["fixture-sample"],
            nodes=[component, resource],
            edges=[edge],
            metadata={"fixture": True},
        )
    )

    with pytest.raises(InvalidKnowledgeContextError):
        search_fixture(knowledge)


def test_two_vulnerabilities_on_one_register_produce_two_candidates(
    synthetic_arm_knowledge_sample: VulnerabilitySample,
) -> None:
    """One behavior anchor expands to two independent vulnerability candidates."""

    second_data = synthetic_arm_knowledge_sample.model_dump(mode="json")
    second_data["id"] = "FIXTURE-ARM-KG-002"
    knowledge = NetworkXKnowledgeGraphRepository.from_bundle(
        VulnerabilityKnowledgeBuilder().build_many(
            [
                synthetic_arm_knowledge_sample,
                VulnerabilitySample.model_validate(second_data),
            ]
        )
    )

    first = search_fixture(knowledge)
    second = search_fixture(knowledge)

    assert first == second
    assert len(first) == 2
    assert len({item.entity_link.id for item in first}) == 2
    assert {item.knowledge_vulnerability_id for item in first} == {
        "vulnerability:FIXTURE-ARM-KG-001",
        "vulnerability:FIXTURE-ARM-KG-002",
    }
    assert search_fixture(knowledge, top_n=1) == first[:1]


def test_candidate_search_does_not_modify_source_repositories(
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
) -> None:
    """Phase 6 is read-only and creates no merged or cross-graph edges."""

    behavior = make_behavior_repository()
    behavior_before = (
        behavior.list_nodes(),
        behavior.list_edges(),
        behavior.metadata,
    )
    knowledge_before = (
        synthetic_arm_knowledge_repository.list_nodes(),
        synthetic_arm_knowledge_repository.list_edges(),
        synthetic_arm_knowledge_repository.list_evidence(),
        synthetic_arm_knowledge_repository.metadata,
    )

    assert search_fixture(
        synthetic_arm_knowledge_repository,
        behavior=behavior,
    )

    assert behavior_before == (
        behavior.list_nodes(),
        behavior.list_edges(),
        behavior.metadata,
    )
    assert knowledge_before == (
        synthetic_arm_knowledge_repository.list_nodes(),
        synthetic_arm_knowledge_repository.list_edges(),
        synthetic_arm_knowledge_repository.list_evidence(),
        synthetic_arm_knowledge_repository.metadata,
    )
