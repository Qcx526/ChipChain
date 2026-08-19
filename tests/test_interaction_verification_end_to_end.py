"""Owned ARM ELF end-to-end regression for Type II verification."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from chipchain.models import CrossLayerLocationRole
from chipchain.verification import (ConditionStatus, InteractionVerificationStatus,
    VerificationCapabilityStatus, VerificationStatus)
from examples.arm_interaction_verification_demo import build_demo_result

pytest.importorskip("angr")
pytestmark = pytest.mark.angr
ROOT = Path(__file__).resolve().parents[1]


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


def test_type2_demo_prints_verification_boundaries():
    completed = subprocess.run([sys.executable, "examples/arm_interaction_verification_demo.py"],
        cwd=ROOT, check=True, capture_output=True, text=True)
    assert "Interaction Type: firmware_behavior_to_hardware" in completed.stdout
    assert "Capability: partially_supported" in completed.stdout
    assert "Location Role: cross_layer_trigger_point" in completed.stdout
    assert "Hardware Address: 0x40000000" in completed.stdout
    assert "Initiating Firmware Vulnerability: not required by Type II" in completed.stdout
    assert "This is not a verified attack chain." in completed.stdout
