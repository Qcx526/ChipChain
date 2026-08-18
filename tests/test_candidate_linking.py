"""Tests for Phase 6A exact hardware entity linking."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from chipchain.candidate import (
    CandidateArchitectureMismatchError,
    EntityLink,
    EntityLinkMethod,
    ExactHardwareEntityLinker,
)
from chipchain.graph import NetworkXGraphRepository
from chipchain.knowledge import (
    KnowledgeGraphBundle,
    KnowledgeNode,
    NetworkXKnowledgeGraphRepository,
    VulnerabilityKnowledgeBuilder,
)
from chipchain.models import (
    Architecture,
    BehaviorNode,
    Layer,
    NodeKind,
    VulnerabilitySample,
)

BEHAVIOR_ANCHOR_ID = "fixture-behavior-register"


def make_behavior_repository(
    *,
    address: str | None = "0x40000000",
    metadata: dict[str, object] | None = None,
    name: str = "FIXTURE_MMIO_REGISTER",
) -> NetworkXGraphRepository:
    """Create one ARM hardware-node repository for exact-link tests."""

    repository = NetworkXGraphRepository(metadata={"fixture": True})
    repository.add_node(
        BehaviorNode(
            id=BEHAVIOR_ANCHOR_ID,
            kind=NodeKind.REGISTER,
            name=name,
            architecture=Architecture.ARM,
            layer=Layer.HARDWARE,
            address=address,
            metadata=metadata or {},
        )
    )
    return repository


def test_entity_link_is_deterministic_strict_and_round_trips() -> None:
    """Exact links have reproducible IDs and cannot use fuzzy methods or empty keys."""

    values = {
        "architecture": Architecture.ARM,
        "behavior_node_id": BEHAVIOR_ANCHOR_ID,
        "knowledge_node_id": "fixture-knowledge-resource",
        "behavior_node_kind": NodeKind.REGISTER,
        "knowledge_node_kind": "hardware_resource",
        "match_keys": ["arch:arm:address:0x40000000"],
    }
    first = EntityLink.create(**values)  # type: ignore[arg-type]
    second = EntityLink.create(**values)  # type: ignore[arg-type]
    restored = EntityLink.model_validate_json(first.model_dump_json())

    assert first == second == restored
    assert first.link_method is EntityLinkMethod.EXACT_CANONICAL_KEY
    assert first.id.startswith("entity-link:arm:")
    with pytest.raises(ValidationError):
        EntityLink.model_validate({**first.model_dump(mode="json"), "match_keys": []})
    with pytest.raises(ValidationError):
        EntityLink.model_validate(
            {**first.model_dump(mode="json"), "link_method": "fuzzy"}
        )
    with pytest.raises(ValidationError, match="deterministic identity"):
        EntityLink.model_validate(
            {**first.model_dump(mode="json"), "id": "entity-link:arm:wrong"}
        )
    wrong_key_architecture = first.model_dump(mode="json")
    wrong_key_architecture["match_keys"] = ["arch:risc_v:address:0x40000000"]
    with pytest.raises(ValidationError, match="match link architecture"):
        EntityLink.model_validate(wrong_key_architecture)


def test_exact_hardware_link_matches_both_phase4b_keys(
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
) -> None:
    """Address and memory-map keys intersect without using entity names."""

    behavior = make_behavior_repository(
        metadata={
            "memory_map_id": "synthetic-arm-mmio-map",
            "memory_map_region": "fixture-mmio-register",
        }
    )
    result = ExactHardwareEntityLinker().link(
        behavior,
        synthetic_arm_knowledge_repository,
        architecture=Architecture.ARM,
    )

    assert len(result.links) == 1
    assert result.links[0].match_keys == [
        "arch:arm:address:0x40000000",
        (
            "arch:arm:mmio-map:synthetic-arm-mmio-map:"
            "region:fixture-mmio-register"
        ),
    ]
    assert result.unmatched_behavior_node_ids == []
    assert result.unmatched_knowledge_node_ids == []


def test_linker_allows_one_behavior_anchor_to_many_knowledge_resources(
    synthetic_arm_knowledge_sample: VulnerabilitySample,
) -> None:
    """Multiple vulnerability samples sharing a register produce multiple links."""

    second_data = synthetic_arm_knowledge_sample.model_dump(mode="json")
    second_data["id"] = "FIXTURE-ARM-KG-002"
    bundle = VulnerabilityKnowledgeBuilder().build_many(
        [
            synthetic_arm_knowledge_sample,
            VulnerabilitySample.model_validate(second_data),
        ]
    )
    knowledge = NetworkXKnowledgeGraphRepository.from_bundle(bundle)
    result = ExactHardwareEntityLinker().link(
        make_behavior_repository(),
        knowledge,
        architecture=Architecture.ARM,
    )

    assert len(result.links) == 2
    assert {link.behavior_node_id for link in result.links} == {
        BEHAVIOR_ANCHOR_ID
    }
    assert len({link.knowledge_node_id for link in result.links}) == 2


def test_linker_never_uses_name_similarity_or_different_address(
    synthetic_arm_knowledge_repository: NetworkXKnowledgeGraphRepository,
) -> None:
    """Equal labels without keys and unequal addresses remain unmatched."""

    no_keys = ExactHardwareEntityLinker().link(
        make_behavior_repository(address=None),
        synthetic_arm_knowledge_repository,
        architecture=Architecture.ARM,
    )
    wrong_address = ExactHardwareEntityLinker().link(
        make_behavior_repository(address="0x40000004"),
        synthetic_arm_knowledge_repository,
        architecture=Architecture.ARM,
    )

    assert no_keys.links == []
    assert no_keys.unmatched_behavior_node_ids == [BEHAVIOR_ANCHOR_ID]
    assert wrong_address.links == []


def test_knowledge_node_without_match_key_is_reported_unmatched() -> None:
    """A hardware label alone cannot establish cross-graph identity."""

    node = KnowledgeNode(
        id="fixture-knowledge-resource",
        kind="hardware_resource",
        label="FIXTURE_MMIO_REGISTER",
        architecture="arm",
        layer="hardware",
        match_keys=[],
        metadata={"fixture": True},
    )
    knowledge = NetworkXKnowledgeGraphRepository.from_bundle(
        KnowledgeGraphBundle(
            architecture="arm",
            sample_ids=["fixture-sample"],
            nodes=[node],
            metadata={"fixture": True},
        )
    )

    result = ExactHardwareEntityLinker().link(
        make_behavior_repository(),
        knowledge,
        architecture=Architecture.ARM,
    )

    assert result.links == []
    assert result.unmatched_knowledge_node_ids == [node.id]


def test_architecture_filter_rejects_riscv_knowledge_repository() -> None:
    """An ARM behavior graph cannot enter a RISC-V knowledge graph."""

    knowledge = NetworkXKnowledgeGraphRepository(architecture="risc_v")

    with pytest.raises(CandidateArchitectureMismatchError):
        ExactHardwareEntityLinker().link(
            make_behavior_repository(),
            knowledge,
            architecture=Architecture.ARM,
        )


def test_cwe_and_capec_cannot_be_entity_link_endpoints() -> None:
    """Global taxonomy kinds are invalid hardware EntityLink endpoints."""

    with pytest.raises(ValidationError, match="hardware resource"):
        EntityLink.create(
            architecture=Architecture.ARM,
            behavior_node_id=BEHAVIOR_ANCHOR_ID,
            knowledge_node_id="cwe:CWE-284",
            behavior_node_kind=NodeKind.REGISTER,
            knowledge_node_kind="cwe",  # type: ignore[arg-type]
            match_keys=["arch:arm:address:0x40000000"],
        )
