"""Public Phase 9C machine-level hardware-trigger contract API."""

from chipchain.hardware_trigger.enums import (
    ArmExecutionMode,
    ArmPrivilegeMode,
    HardwareFailureEffectKind,
    HardwareTriggerProofKind,
)
from chipchain.hardware_trigger.errors import (
    HardwareTriggerMatchingError,
    InvalidTriggerMatchingInputError,
    UnsupportedTriggerArtifactError,
)
from chipchain.hardware_trigger.angr_matcher import AngrFirmwareTriggerMatcher
from chipchain.hardware_trigger.matcher import FirmwareTriggerMatcher
from chipchain.hardware_trigger.models import (
    ArmMemoryPrecondition,
    ArmRegisterPrecondition,
    HardwareFailureEffect,
    HardwareTriggerPreconditions,
    HardwareTriggerProof,
    HardwareTriggerSignature,
    hardware_trigger_signature_id,
)
from chipchain.hardware_trigger.static_models import (
    StaticFirmwareTriggerMatch,
    StaticFirmwareTriggerMatchResult,
    StaticInstructionLocation,
    static_firmware_trigger_match_id,
)

__all__ = [
    "ArmExecutionMode",
    "ArmMemoryPrecondition",
    "ArmPrivilegeMode",
    "ArmRegisterPrecondition",
    "AngrFirmwareTriggerMatcher",
    "FirmwareTriggerMatcher",
    "HardwareFailureEffect",
    "HardwareFailureEffectKind",
    "HardwareTriggerPreconditions",
    "HardwareTriggerProof",
    "HardwareTriggerProofKind",
    "HardwareTriggerSignature",
    "HardwareTriggerMatchingError",
    "InvalidTriggerMatchingInputError",
    "StaticFirmwareTriggerMatch",
    "StaticFirmwareTriggerMatchResult",
    "StaticInstructionLocation",
    "UnsupportedTriggerArtifactError",
    "hardware_trigger_signature_id",
    "static_firmware_trigger_match_id",
]
