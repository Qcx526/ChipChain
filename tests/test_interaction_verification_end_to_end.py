"""Owned ARM ELF end-to-end regression for Type II verification."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from chipchain.models import (
    Architecture,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    CrossLayerLocationRole,
    Layer,
)
from chipchain.verification import (ConditionStatus, InteractionVerificationStatus,
    VerificationCapabilityStatus, VerificationStatus,
    InteractionReferenceBinding, InteractionReferenceRole,
    InteractionSourceKind, InteractionVerificationInput,
    InteractionVerificationPipeline, RequiredFactCategory)
from examples.arm_interaction_verification_demo import (
    build_demo_material,
    build_demo_result,
)

pytest.importorskip("angr")
pytestmark = pytest.mark.angr
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def owned_demo_material():
    return build_demo_material()


def test_owned_arm_mmio_type2_verification_is_conservative_and_role_aware():
    interaction, _, result = build_demo_result()
    assert interaction.initiating_vulnerability_ids == []
    assert result.capability_status is VerificationCapabilityStatus.PARTIALLY_SUPPORTED
    assert [record.status for record in result.behavior_edge_verifications] == [
        VerificationStatus.VERIFIED, VerificationStatus.VERIFIED]
    assert result.entity_link_verifications[0].status is VerificationStatus.VERIFIED
    assert all(item.status is ConditionStatus.UNKNOWN for item in result.condition_assessments)
    assert result.verification_status is InteractionVerificationStatus.PARTIALLY_VERIFIED
    assert 0.0 < result.verification_score < 1.0
    location = result.location_findings[0]
    assert location.role is CrossLayerLocationRole.CROSS_LAYER_TRIGGER_POINT
    assert location.instruction_address.value == "0x10008"
    assert location.hardware_address.value == "0x40000000"
    assert location.source_line is None
    assert result.trigger_features.cwe_ids == []
    assert result.trigger_features.capec_ids == []
    provenance_ids = {item.feature_id for item in result.trigger_features.provenance}
    assert "hardware_address:0x40000000" in provenance_ids
    assert "memory_map_id:synthetic-arm-mmio-map" in provenance_ids
    assert "memory_map_region:fixture-mmio-register" in provenance_ids
    assert "mmio_access:mmio_write" in provenance_ids
    assert result.required_fact_statuses[
        RequiredFactCategory.CROSS_LAYER_TRANSITION_SUPPORT
    ] is VerificationStatus.VERIFIED


def test_unbound_verified_legacy_candidate_cannot_support_transition_or_partial(
    owned_demo_material,
):
    interaction, _, candidate, behavior, knowledge, resolver = owned_demo_material
    verification_input = InteractionVerificationInput.create(
        interaction, legacy_candidate_id=candidate.id
    )
    result = InteractionVerificationPipeline().verify(
        interaction,
        verification_input,
        behavior,
        knowledge,
        resolver,
        legacy_candidate=candidate,
    )
    assert all(
        record.status is VerificationStatus.VERIFIED
        for record in result.behavior_edge_verifications
    )
    assert result.entity_link_verifications[0].status is VerificationStatus.VERIFIED
    assert result.required_fact_statuses[
        RequiredFactCategory.CROSS_LAYER_TRANSITION_SUPPORT
    ] is VerificationStatus.UNKNOWN
    assert result.verification_status is InteractionVerificationStatus.INSUFFICIENT_EVIDENCE
    assert result.evidence_inventory.verified_non_llm_evidence_count == 0


def test_wrong_interaction_resource_binding_cannot_verify_transition(
    owned_demo_material,
):
    _, _, candidate, behavior, knowledge, resolver = owned_demo_material
    interaction = CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
        source_layer=Layer.DRIVER,
        target_layer=Layer.HARDWARE,
        target_vulnerability_ids=["synthetic-target-A"],
        trigger_behavior_ids=["trigger-A"],
        hardware_resource_ids=["resource-A"],
    )
    bindings = [
        InteractionReferenceBinding(
            interaction_reference_id="trigger-A",
            reference_role=InteractionReferenceRole.TRIGGER_BEHAVIOR,
            source_kind=InteractionSourceKind.BEHAVIOR_EDGE,
            source_id=candidate.behavior_path.edge_ids[-1],
        ),
        InteractionReferenceBinding(
            interaction_reference_id="resource-A",
            reference_role=InteractionReferenceRole.HARDWARE_RESOURCE,
            source_kind=InteractionSourceKind.ENTITY_LINK,
            source_id=candidate.entity_link.id,
        ),
    ]
    verification_input = InteractionVerificationInput.create(
        interaction, bindings=bindings, legacy_candidate_id=candidate.id
    )
    result = InteractionVerificationPipeline().verify(
        interaction,
        verification_input,
        behavior,
        knowledge,
        resolver,
        legacy_candidate=candidate,
    )
    resource_record = next(
        item
        for item in result.binding_verifications
        if item.subject_id.startswith("hardware_resource:")
    )
    assert resource_record.status is VerificationStatus.UNKNOWN
    assert result.required_fact_statuses[
        RequiredFactCategory.CROSS_LAYER_TRANSITION_SUPPORT
    ] is VerificationStatus.UNKNOWN


def test_bound_calls_edge_cannot_replace_bound_mmio_transition(
    owned_demo_material,
):
    _, _, candidate, behavior, knowledge, resolver = owned_demo_material
    interaction = CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
        source_layer=Layer.DRIVER,
        target_layer=Layer.HARDWARE,
        target_vulnerability_ids=["synthetic-target"],
        trigger_behavior_ids=["call-trigger"],
        hardware_resource_ids=["fixture-mmio-register"],
    )
    bindings = [
        InteractionReferenceBinding(
            interaction_reference_id="call-trigger",
            reference_role=InteractionReferenceRole.TRIGGER_BEHAVIOR,
            source_kind=InteractionSourceKind.BEHAVIOR_EDGE,
            source_id=candidate.behavior_path.edge_ids[0],
        ),
        InteractionReferenceBinding(
            interaction_reference_id="fixture-mmio-register",
            reference_role=InteractionReferenceRole.HARDWARE_RESOURCE,
            source_kind=InteractionSourceKind.ENTITY_LINK,
            source_id=candidate.entity_link.id,
        ),
    ]
    result = InteractionVerificationPipeline().verify(
        interaction,
        InteractionVerificationInput.create(
            interaction, bindings=bindings, legacy_candidate_id=candidate.id
        ),
        behavior,
        knowledge,
        resolver,
        legacy_candidate=candidate,
    )
    assert result.behavior_edge_verifications[0].status is VerificationStatus.VERIFIED
    assert result.required_fact_statuses[
        RequiredFactCategory.CROSS_LAYER_TRANSITION_SUPPORT
    ] is VerificationStatus.UNKNOWN


def test_type2_demo_prints_verification_boundaries():
    completed = subprocess.run([sys.executable, "examples/arm_interaction_verification_demo.py"],
        cwd=ROOT, check=True, capture_output=True, text=True)
    assert "Interaction Type: firmware_behavior_to_hardware" in completed.stdout
    assert "Capability: partially_supported" in completed.stdout
    assert "Location Role: cross_layer_trigger_point" in completed.stdout
    assert "Hardware Address: 0x40000000" in completed.stdout
    assert "Initiating Firmware Vulnerability: not required by Type II" in completed.stdout
    assert "This is not a verified attack chain." in completed.stdout
