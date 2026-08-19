"""Deterministic required-fact profiles for the three interaction types."""

from pydantic import Field

from chipchain.models import CrossLayerInteractionType
from chipchain.models.common import DomainModel
from chipchain.verification.enums import RequiredFactCategory, VerificationCapabilityStatus


class InteractionVerificationRequirements(DomainModel):
    interaction_type: CrossLayerInteractionType
    capability_status: VerificationCapabilityStatus
    required_facts: list[RequiredFactCategory] = Field(default_factory=list)
    unsupported_facts: list[RequiredFactCategory] = Field(default_factory=list)


def build_interaction_requirements(
    interaction_type: CrossLayerInteractionType,
) -> InteractionVerificationRequirements:
    common = [RequiredFactCategory.ARCHITECTURE_RULES, RequiredFactCategory.CONDITIONS]
    if interaction_type is CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE:
        facts = [RequiredFactCategory.INITIATING_VULNERABILITY_SUPPORT,
                 RequiredFactCategory.TRIGGER_BEHAVIOR_SUPPORT,
                 RequiredFactCategory.CROSS_LAYER_TRANSITION_SUPPORT,
                 RequiredFactCategory.TARGET_VULNERABILITY_SUPPORT, *common]
        return InteractionVerificationRequirements(interaction_type=interaction_type,
            capability_status=VerificationCapabilityStatus.PARTIALLY_SUPPORTED, required_facts=facts)
    if interaction_type is CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE:
        facts = [RequiredFactCategory.TRIGGER_BEHAVIOR_SUPPORT,
                 RequiredFactCategory.CROSS_LAYER_TRANSITION_SUPPORT,
                 RequiredFactCategory.TARGET_VULNERABILITY_SUPPORT, *common]
        return InteractionVerificationRequirements(interaction_type=interaction_type,
            capability_status=VerificationCapabilityStatus.PARTIALLY_SUPPORTED, required_facts=facts)
    unsupported = [RequiredFactCategory.INITIATING_VULNERABILITY_SUPPORT,
                   RequiredFactCategory.HARDWARE_FAULT_STATE_SUPPORT,
                   RequiredFactCategory.PROPAGATION_MECHANISM_SUPPORT,
                   RequiredFactCategory.AFFECTED_EXECUTION_SUPPORT, *common]
    return InteractionVerificationRequirements(interaction_type=interaction_type,
        capability_status=VerificationCapabilityStatus.NOT_IMPLEMENTED,
        required_facts=unsupported, unsupported_facts=unsupported)
