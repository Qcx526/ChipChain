"""Public Phase 9C machine-level hardware-trigger contract API."""

from chipchain.hardware_trigger.enums import (
    ArmExecutionMode,
    ArmPrivilegeMode,
    HardwareFailureEffectKind,
    HardwareTriggerProofKind,
)
from chipchain.hardware_trigger.errors import (
    HardwareTriggerMatchingError,
    InvalidRuntimeTriggerInputError,
    InvalidTriggerMatchingInputError,
    RuntimeTriggerBindingError,
    RuntimeTriggerMatchingError,
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
from chipchain.hardware_trigger.runtime_matcher import RuntimeFirmwareTriggerMatcher
from chipchain.hardware_trigger.runtime_models import (
    RuntimeFirmwareTriggerMatchResult,
    RuntimeFirmwareTriggerOccurrence,
    RuntimeInstructionOccurrence,
    RuntimeTriggerExecutionTrace,
    canonical_raw_instruction_bytes,
    raw_little_endian_a32_word,
    runtime_firmware_trigger_occurrence_id,
    runtime_trigger_execution_trace_id,
    static_trigger_result_sha256,
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
    "InvalidRuntimeTriggerInputError",
    "RuntimeFirmwareTriggerMatcher",
    "RuntimeFirmwareTriggerMatchResult",
    "RuntimeFirmwareTriggerOccurrence",
    "RuntimeInstructionOccurrence",
    "RuntimeTriggerBindingError",
    "RuntimeTriggerExecutionTrace",
    "RuntimeTriggerMatchingError",
    "StaticFirmwareTriggerMatch",
    "StaticFirmwareTriggerMatchResult",
    "StaticInstructionLocation",
    "UnsupportedTriggerArtifactError",
    "hardware_trigger_signature_id",
    "canonical_raw_instruction_bytes",
    "raw_little_endian_a32_word",
    "runtime_firmware_trigger_occurrence_id",
    "runtime_trigger_execution_trace_id",
    "static_firmware_trigger_match_id",
    "static_trigger_result_sha256",
]
