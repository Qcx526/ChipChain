"""Validation helpers for explicit interaction reference bindings."""

from chipchain.models import CrossLayerInteraction
from chipchain.verification.enums import InteractionReferenceRole
from chipchain.verification.errors import VerificationInputError
from chipchain.verification.models import InteractionReferenceBinding

_FIELD_BY_ROLE = {
    InteractionReferenceRole.INITIATING_VULNERABILITY: "initiating_vulnerability_ids",
    InteractionReferenceRole.TARGET_VULNERABILITY: "target_vulnerability_ids",
    InteractionReferenceRole.TRIGGER_BEHAVIOR: "trigger_behavior_ids",
    InteractionReferenceRole.PROPAGATION_BEHAVIOR: "propagation_behavior_ids",
    InteractionReferenceRole.AFFECTED_EXECUTION: "affected_execution_ids",
    InteractionReferenceRole.FAULT_STATE: "fault_state_ids",
    InteractionReferenceRole.HARDWARE_RESOURCE: "hardware_resource_ids",
    InteractionReferenceRole.SECURITY_MECHANISM: "security_mechanism_ids",
}


def validate_reference_bindings(
    interaction: CrossLayerInteraction, bindings: list[InteractionReferenceBinding]
) -> None:
    """Reject role/reference pairs that are absent from the semantic contract."""

    for binding in bindings:
        values = getattr(interaction, _FIELD_BY_ROLE[binding.reference_role])
        if binding.interaction_reference_id not in values:
            raise VerificationInputError(
                f"{binding.reference_role.value} binding references an ID outside the interaction contract"
            )
    if not interaction.initiating_vulnerability_ids and any(
        b.reference_role is InteractionReferenceRole.INITIATING_VULNERABILITY for b in bindings
    ):
        raise VerificationInputError("interaction does not permit an initiating vulnerability binding")
