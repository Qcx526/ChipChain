"""Fail-closed validation for Phase 9B2A dynamic trigger bindings."""

from __future__ import annotations

from pydantic import ValidationError

from chipchain.models import (
    CrossLayerDirection,
    CrossLayerInteraction,
    CrossLayerInteractionType,
)
from chipchain.runtime.enums import RuntimeEventKind
from chipchain.verification.dynamic_models import (
    DynamicTriggerFact,
    DynamicTriggerObservationBinding,
)
from chipchain.verification.enums import InteractionReferenceRole
from chipchain.verification.errors import VerificationInputError


_SUPPORTED_INTERACTION_TYPES = {
    CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
    CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
}
_SUPPORTED_TRIGGER_EVENTS = {
    RuntimeEventKind.MMIO_READ,
    RuntimeEventKind.MMIO_WRITE,
}


def validate_dynamic_trigger_bindings(
    interaction: CrossLayerInteraction,
    trigger_facts: list[DynamicTriggerFact],
    observation_bindings: list[DynamicTriggerObservationBinding],
) -> None:
    """Validate explicit trigger linkage without inspecting runtime artifacts.

    This boundary validates only model identity, interaction scope, and binding
    cardinality. It does not resolve RuntimeTrace or Evidence objects and does
    not produce a verification decision.
    """

    validated_interaction = _snapshot_interaction(interaction)
    if (
        validated_interaction.interaction_type
        is CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
    ):
        raise VerificationInputError(
            "Phase 9B2A Type III dynamic binding is explicitly not implemented"
        )
    if validated_interaction.interaction_type not in _SUPPORTED_INTERACTION_TYPES:
        raise VerificationInputError(
            "dynamic trigger binding requires a supported Type I/II interaction"
        )
    if (
        validated_interaction.direction
        is not CrossLayerDirection.SOFTWARE_TO_HARDWARE
    ):
        raise VerificationInputError(
            "dynamic trigger binding requires software-to-hardware direction"
        )

    facts = [_snapshot_fact(item) for item in trigger_facts]
    bindings = [_snapshot_binding(item) for item in observation_bindings]
    _require_unique([item.id for item in facts], "dynamic trigger fact IDs")
    _require_unique([item.id for item in bindings], "dynamic binding IDs")

    fact_by_id: dict[str, DynamicTriggerFact] = {}
    for fact in facts:
        if fact.interaction_id != validated_interaction.id:
            raise VerificationInputError(
                "dynamic trigger fact interaction_id does not match interaction"
            )
        if fact.architecture is not validated_interaction.architecture:
            raise VerificationInputError(
                "dynamic trigger fact architecture does not match interaction"
            )
        if fact.interaction_type is not validated_interaction.interaction_type:
            raise VerificationInputError(
                "dynamic trigger fact type does not match interaction"
            )
        if fact.direction is not validated_interaction.direction:
            raise VerificationInputError(
                "dynamic trigger fact direction does not match interaction"
            )
        if (
            fact.interaction_reference_id
            not in validated_interaction.trigger_behavior_ids
        ):
            raise VerificationInputError(
                "dynamic interaction_reference_id is outside trigger_behavior_ids"
            )
        if fact.reference_role is not InteractionReferenceRole.TRIGGER_BEHAVIOR:
            raise VerificationInputError(
                "dynamic trigger fact reference_role must be trigger_behavior"
            )
        if fact.event_kind not in _SUPPORTED_TRIGGER_EVENTS:
            raise VerificationInputError(
                "dynamic trigger event_kind must be mmio_read or mmio_write"
            )
        fact_by_id[fact.id] = fact

    linkage_keys: list[tuple[str, str, str]] = []
    evidence_ids: list[str] = []
    observation_facts: dict[tuple[str, str], str] = {}
    for binding in bindings:
        if binding.interaction_id != validated_interaction.id:
            raise VerificationInputError(
                "dynamic binding interaction_id does not match interaction"
            )
        fact = fact_by_id.get(binding.dynamic_trigger_fact_id)
        if fact is None:
            raise VerificationInputError("dynamic binding references an unknown fact")
        try:
            binding.validate_against(fact)
        except ValueError as exc:
            raise VerificationInputError(
                "dynamic binding does not match its trigger fact"
            ) from exc

        linkage_key = (
            binding.dynamic_trigger_fact_id,
            binding.runtime_trace_id,
            binding.runtime_observation_id,
        )
        linkage_keys.append(linkage_key)
        evidence_ids.append(binding.dynamic_evidence_id)
        observation_key = (
            binding.runtime_trace_id,
            binding.runtime_observation_id,
        )
        existing_fact_id = observation_facts.get(observation_key)
        if (
            existing_fact_id is not None
            and existing_fact_id != binding.dynamic_trigger_fact_id
        ):
            raise VerificationInputError(
                "one runtime observation cannot bind conflicting trigger facts"
            )
        observation_facts[observation_key] = binding.dynamic_trigger_fact_id

    _require_unique(linkage_keys, "dynamic binding linkage")
    _require_unique(evidence_ids, "dynamic binding Evidence IDs")


def _snapshot_interaction(
    interaction: CrossLayerInteraction,
) -> CrossLayerInteraction:
    try:
        return CrossLayerInteraction.model_validate(
            interaction.model_dump(mode="json")
        )
    except ValidationError as exc:
        raise VerificationInputError(
            "dynamic binding interaction revalidation failed"
        ) from exc


def _snapshot_fact(fact: DynamicTriggerFact) -> DynamicTriggerFact:
    try:
        return DynamicTriggerFact.model_validate(fact.model_dump(mode="json"))
    except ValidationError as exc:
        raise VerificationInputError(
            "dynamic trigger fact revalidation failed"
        ) from exc


def _snapshot_binding(
    binding: DynamicTriggerObservationBinding,
) -> DynamicTriggerObservationBinding:
    try:
        return DynamicTriggerObservationBinding.model_validate(
            binding.model_dump(mode="json")
        )
    except ValidationError as exc:
        raise VerificationInputError("dynamic binding revalidation failed") from exc


def _require_unique(values: list[object], label: str) -> None:
    if len(values) != len(set(values)):
        raise VerificationInputError(f"{label} must be unique")
