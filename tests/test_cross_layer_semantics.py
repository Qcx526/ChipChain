"""Phase 8R formal cross-layer semantics and compatibility tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.candidate import (
    CrossGraphCandidateSearcher,
    CrossLayerSearchStrategy,
    UnsupportedCrossLayerSearchError,
    require_supported_search_strategy,
    search_strategy_for_direction,
)
from chipchain.models import (
    Architecture,
    CrossLayerDirection,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    CrossLayerLocationRole,
    HARDWARE_SIDE_LAYERS,
    Layer,
    RelationType,
    SOFTWARE_SIDE_LAYERS,
    VulnerabilitySample,
    direction_for_interaction_type,
)

FIXTURE_DIRECTORY = Path(__file__).parent / "fixtures" / "cross_layer"


def _load(name: str) -> dict[str, object]:
    return json.loads((FIXTURE_DIRECTORY / name).read_text(encoding="utf-8"))


def _valid(interaction_type: CrossLayerInteractionType) -> dict[str, object]:
    names = {
        CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE: (
            "type1_fw_vuln_to_hw.json"
        ),
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE: (
            "type2_fw_behavior_to_hw.json"
        ),
        CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE: (
            "type3_hw_vuln_to_fw.json"
        ),
    }
    return _load(names[interaction_type])


def test_interaction_type_is_exactly_the_three_formal_classes():
    assert {item.value for item in CrossLayerInteractionType} == {
        "firmware_vulnerability_to_hardware",
        "firmware_behavior_to_hardware",
        "hardware_vulnerability_to_firmware",
    }


def test_direction_is_closed_to_two_physical_directions():
    assert {item.value for item in CrossLayerDirection} == {
        "software_to_hardware",
        "hardware_to_software",
    }


def test_software_and_hardware_side_layer_sets_are_explicit():
    assert SOFTWARE_SIDE_LAYERS == {
        Layer.FIRMWARE,
        Layer.DRIVER,
        Layer.INTERFACE,
    }
    assert HARDWARE_SIDE_LAYERS == {Layer.HARDWARE}


@pytest.mark.parametrize(
    "interaction_type,expected",
    [
        (
            CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
            CrossLayerDirection.SOFTWARE_TO_HARDWARE,
        ),
        (
            CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
            CrossLayerDirection.SOFTWARE_TO_HARDWARE,
        ),
        (
            CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE,
            CrossLayerDirection.HARDWARE_TO_SOFTWARE,
        ),
    ],
)
def test_type_to_direction_mapping_is_deterministic(interaction_type, expected):
    assert direction_for_interaction_type(interaction_type) is expected


@pytest.mark.parametrize(
    "name",
    [
        "type1_fw_vuln_to_hw.json",
        "type2_fw_behavior_to_hw.json",
        "type3_hw_vuln_to_fw.json",
    ],
)
def test_semantic_fixtures_round_trip_and_are_clearly_synthetic(name: str):
    data = _load(name)
    interaction = CrossLayerInteraction.model_validate(data)
    restored = CrossLayerInteraction.model_validate_json(
        interaction.model_dump_json()
    )
    assert restored == interaction
    assert interaction.metadata["fixture"] is True
    assert interaction.metadata["synthetic"] is True
    assert interaction.metadata["owned"] is True
    assert interaction.metadata["not_a_real_cve"] is True
    assert interaction.metadata["not_a_benchmark"] is True


def test_interaction_id_is_canonical_and_independent_of_input_list_order():
    first = CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=(
            CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
        ),
        source_layer=Layer.HARDWARE,
        target_layer=Layer.FIRMWARE,
        initiating_vulnerability_ids=["hw-b", "hw-a"],
        affected_execution_ids=["exec-b", "exec-a"],
        fault_state_ids=["fault"],
        referenced_architectures=[Architecture.ARM],
    )
    second = CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=(
            CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
        ),
        source_layer=Layer.HARDWARE,
        target_layer=Layer.FIRMWARE,
        initiating_vulnerability_ids=["hw-a", "hw-b"],
        affected_execution_ids=["exec-a", "exec-b"],
        fault_state_ids=["fault"],
        referenced_architectures=[Architecture.ARM],
    )
    assert first.id == second.id
    assert first == second
    assert len(first.id.rsplit(":", 1)[1]) == 64


@pytest.mark.parametrize(
    "interaction_type,field,error",
    [
        (
            CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
            "initiating_vulnerability_ids",
            "initiating software-side vulnerability",
        ),
        (
            CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
            "target_vulnerability_ids",
            "target hardware-side vulnerability",
        ),
        (
            CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
            "trigger_behavior_ids",
            "trigger behavior",
        ),
        (
            CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
            "target_vulnerability_ids",
            "target hardware-side vulnerability",
        ),
        (
            CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
            "trigger_behavior_ids",
            "trigger behavior",
        ),
        (
            CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE,
            "initiating_vulnerability_ids",
            "initiating hardware-side vulnerability",
        ),
        (
            CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE,
            "affected_execution_ids",
            "affected software execution",
        ),
    ],
)
def test_required_participants_are_enforced(interaction_type, field, error):
    data = _valid(interaction_type)
    data[field] = []
    with pytest.raises(ValidationError, match=error):
        CrossLayerInteraction.model_validate(data)


def test_type_two_rejects_an_invented_firmware_vulnerability():
    data = _valid(CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE)
    data["initiating_vulnerability_ids"] = ["invented-firmware-vulnerability"]
    with pytest.raises(ValidationError, match="must not invent"):
        CrossLayerInteraction.model_validate(data)


def test_type_two_explicitly_supports_no_initiating_vulnerability():
    interaction = CrossLayerInteraction.model_validate(
        _valid(CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE)
    )
    assert interaction.initiating_vulnerability_ids == []
    assert interaction.trigger_behavior_ids


def test_type_three_explicitly_supports_no_target_firmware_vulnerability():
    interaction = CrossLayerInteraction.model_validate(
        _valid(CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE)
    )
    assert interaction.target_vulnerability_ids == []
    assert interaction.affected_execution_ids == [
        "fixture-branch-point",
        "fixture-firmware-handler",
    ]


def test_interaction_type_direction_mismatch_is_rejected():
    data = _valid(CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE)
    data["direction"] = CrossLayerDirection.HARDWARE_TO_SOFTWARE.value
    with pytest.raises(ValidationError, match="type and direction"):
        CrossLayerInteraction.model_validate(data)


@pytest.mark.parametrize(
    "interaction_type,field,value",
    [
        (
            CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
            "source_layer",
            Layer.HARDWARE.value,
        ),
        (
            CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
            "target_layer",
            Layer.DRIVER.value,
        ),
        (
            CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE,
            "source_layer",
            Layer.FIRMWARE.value,
        ),
        (
            CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE,
            "target_layer",
            Layer.HARDWARE.value,
        ),
    ],
)
def test_directional_layer_mismatch_is_rejected(interaction_type, field, value):
    data = _valid(interaction_type)
    data[field] = value
    with pytest.raises(ValidationError, match="software|hardware"):
        CrossLayerInteraction.model_validate(data)


def test_explicit_cross_architecture_reference_is_rejected():
    data = _valid(CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE)
    data["referenced_architectures"] = [Architecture.RISC_V.value]
    with pytest.raises(ValidationError, match="architecture must match"):
        CrossLayerInteraction.model_validate(data)


def test_location_roles_separate_cause_trigger_and_affected_execution():
    assert {item.value for item in CrossLayerLocationRole} == {
        "initiating_root_cause",
        "cross_layer_trigger_point",
        "affected_execution_point",
    }


def test_type_three_search_capability_is_explicitly_unsupported():
    assert search_strategy_for_direction(
        CrossLayerDirection.HARDWARE_TO_SOFTWARE
    ) is CrossLayerSearchStrategy.HARDWARE_TO_SOFTWARE_NOT_IMPLEMENTED
    with pytest.raises(
        UnsupportedCrossLayerSearchError,
        match="hardware-to-software.*not implemented",
    ):
        require_supported_search_strategy(
            CrossLayerDirection.HARDWARE_TO_SOFTWARE
        )


def test_legacy_search_capability_remains_exact_anchor():
    assert require_supported_search_strategy(
        CrossLayerDirection.SOFTWARE_TO_HARDWARE
    ) is CrossLayerSearchStrategy.SOFTWARE_TO_HARDWARE_EXACT_ANCHOR


def test_legacy_vulnerability_sample_is_unchanged(arm_vulnerability_data):
    sample = VulnerabilitySample.model_validate(arm_vulnerability_data)
    assert "interaction_type" not in type(sample).model_fields
    assert "cross_layer_interactions" not in type(sample).model_fields


def test_legacy_candidate_api_and_identity_are_unchanged(reasoning_candidate):
    assert reasoning_candidate.id == (
        "cross-graph-candidate:arm:6f564bf5224c568407089b0e"
    )
    assert "interaction_type" not in type(reasoning_candidate).model_fields
    assert "direction" not in type(reasoning_candidate).model_fields


def test_legacy_candidate_search_output_is_unchanged(
    reasoning_behavior_repository,
    synthetic_arm_knowledge_repository,
):
    candidates = CrossGraphCandidateSearcher().search(
        reasoning_behavior_repository,
        synthetic_arm_knowledge_repository,
        architecture=Architecture.ARM,
        start_node_id="phase7-fixture-driver",
        max_hops=1,
    )
    assert [item.id for item in candidates] == [
        "cross-graph-candidate:arm:6f564bf5224c568407089b0e"
    ]
    assert candidates[0].metadata["status"] == "unverified_correlation"


def test_no_hardware_to_firmware_behavior_relation_was_invented():
    assert "affects_execution" not in {item.value for item in RelationType}
    type_three = _load("type3_hw_vuln_to_fw.json")
    assert type_three["metadata"]["no_hardware_to_firmware_behavior_edge"] is True
