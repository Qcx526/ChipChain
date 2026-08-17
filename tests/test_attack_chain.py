"""High-value invariant tests for linear attack chains."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from chipchain.models import AttackChain, ChainStatus


def mark_chain_verified(data: dict[str, Any]) -> None:
    """Mutate fixture data into a structurally verified chain."""

    data["status"] = "verified"
    for edge in data["edges"]:
        edge["verification_status"] = "verified"
    for evidence in data["evidence"]:
        evidence["verified"] = True


def test_valid_linear_arm_chain_loads(arm_chain_data: dict[str, Any]) -> None:
    """The ARM fixture should satisfy all candidate-chain invariants."""

    chain = AttackChain.model_validate(arm_chain_data)

    assert chain.status is ChainStatus.CANDIDATE
    assert len(chain.edges) == len(chain.nodes) - 1


def test_chain_requires_at_least_one_node(arm_chain_data: dict[str, Any]) -> None:
    """An empty path is not an attack chain."""

    arm_chain_data["nodes"] = []
    arm_chain_data["edges"] = []

    with pytest.raises(ValidationError):
        AttackChain.model_validate(arm_chain_data)


@pytest.mark.parametrize("target", ["node", "edge"])
def test_cross_architecture_chain_is_rejected(
    arm_chain_data: dict[str, Any], target: str
) -> None:
    """An ARM chain cannot contain a RISC-V node or edge."""

    if target == "node":
        arm_chain_data["nodes"][1]["architecture"] = "risc_v"
    else:
        arm_chain_data["edges"][1]["architecture"] = "risc_v"

    with pytest.raises(ValidationError, match="architectures must match"):
        AttackChain.model_validate(arm_chain_data)


def test_edge_must_connect_adjacent_nodes(arm_chain_data: dict[str, Any]) -> None:
    """Skipping a node is invalid in the Phase 1 linear-chain model."""

    arm_chain_data["edges"][0]["target_id"] = arm_chain_data["nodes"][2][
        "entity_id"
    ]

    with pytest.raises(ValidationError, match="adjacent ordered nodes"):
        AttackChain.model_validate(arm_chain_data)


@pytest.mark.parametrize("orders", [[0, 1, 1, 3, 4, 5, 6], [0, 2, 3, 4, 5, 6, 7]])
def test_node_orders_must_be_unique_and_contiguous(
    arm_chain_data: dict[str, Any], orders: list[int]
) -> None:
    """Duplicate or non-contiguous node orders must be rejected."""

    for node, order in zip(arm_chain_data["nodes"], orders, strict=True):
        node["order"] = order

    with pytest.raises(ValidationError, match="contiguous from zero"):
        AttackChain.model_validate(arm_chain_data)


def test_edge_count_must_equal_node_count_minus_one(
    arm_chain_data: dict[str, Any],
) -> None:
    """A linear chain has exactly one edge between each adjacent node pair."""

    arm_chain_data["edges"].pop()

    with pytest.raises(ValidationError, match=r"len\(nodes\) - 1"):
        AttackChain.model_validate(arm_chain_data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("score", -0.1),
        ("score", 1.1),
        ("evidence_coverage", -0.1),
        ("evidence_coverage", 1.1),
        ("score_components", {"static_evidence": 1.1}),
    ],
)
def test_chain_scores_must_be_in_unit_interval(
    arm_chain_data: dict[str, Any], field: str, value: object
) -> None:
    """Overall, component, and coverage scores are all bounded."""

    arm_chain_data[field] = value

    with pytest.raises(ValidationError):
        AttackChain.model_validate(arm_chain_data)


def test_chain_rejects_dangling_evidence_reference(
    arm_chain_data: dict[str, Any],
) -> None:
    """Edges may only cite evidence included in the portable chain object."""

    arm_chain_data["edges"][0]["evidence_ids"] = ["missing-evidence"]

    with pytest.raises(ValidationError, match="unknown evidence IDs"):
        AttackChain.model_validate(arm_chain_data)


def test_verified_chain_requires_verified_edges(
    arm_chain_data: dict[str, Any],
) -> None:
    """A verified chain cannot contain an edge that remains unverified."""

    mark_chain_verified(arm_chain_data)
    arm_chain_data["edges"][0]["verification_status"] = "unverified"

    with pytest.raises(ValidationError, match="every edge.*verified"):
        AttackChain.model_validate(arm_chain_data)


def test_verified_chain_requires_evidence_on_each_edge(
    arm_chain_data: dict[str, Any],
) -> None:
    """Verification status alone is insufficient without referenced evidence."""

    mark_chain_verified(arm_chain_data)
    arm_chain_data["edges"][0]["evidence_ids"] = []

    with pytest.raises(ValidationError, match="requires evidence"):
        AttackChain.model_validate(arm_chain_data)


def test_llm_only_evidence_cannot_verify_a_chain(
    arm_chain_data: dict[str, Any],
) -> None:
    """A verified chain needs verified non-LLM evidence on every edge."""

    mark_chain_verified(arm_chain_data)
    first_evidence_id = arm_chain_data["edges"][0]["evidence_ids"][0]
    for evidence in arm_chain_data["evidence"]:
        if evidence["id"] == first_evidence_id:
            evidence["type"] = "llm_semantic"

    with pytest.raises(ValidationError, match="non-LLM evidence"):
        AttackChain.model_validate(arm_chain_data)


def test_verified_chain_with_non_llm_evidence_is_valid(
    arm_chain_data: dict[str, Any],
) -> None:
    """The structural model accepts consistently verified non-LLM evidence."""

    mark_chain_verified(arm_chain_data)

    chain = AttackChain.model_validate(arm_chain_data)

    assert chain.status is ChainStatus.VERIFIED


def test_created_at_must_include_timezone(arm_chain_data: dict[str, Any]) -> None:
    """Naive timestamps are ambiguous and must be rejected."""

    arm_chain_data["created_at"] = "2026-01-01T00:00:00"

    with pytest.raises(ValidationError, match="timezone-aware"):
        AttackChain.model_validate(arm_chain_data)


def test_chain_json_round_trip_preserves_semantics(
    arm_chain_data: dict[str, Any],
) -> None:
    """Attack-chain JSON round trips without losing enum or datetime meaning."""

    chain = AttackChain.model_validate(arm_chain_data)
    restored = AttackChain.model_validate_json(chain.model_dump_json())

    assert restored == chain
