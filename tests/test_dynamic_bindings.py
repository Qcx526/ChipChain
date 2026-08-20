"""Phase 9B2A fail-closed Dynamic Binding validation tests."""

from __future__ import annotations

import pytest

from chipchain.models import (
    Architecture,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    Layer,
)
from chipchain.runtime.enums import RuntimeEventKind
from chipchain.verification.dynamic_bindings import (
    validate_dynamic_trigger_bindings,
)
from chipchain.verification.dynamic_models import (
    DynamicTriggerFact,
    DynamicTriggerObservationBinding,
    dynamic_trigger_fact_id,
    dynamic_trigger_observation_binding_id,
)
from chipchain.verification.enums import InteractionReferenceRole
from chipchain.verification.errors import VerificationInputError
from chipchain.verification.models import HardwareAddress, ProgramAddress


def _interaction(
    *,
    trigger_ids: list[str] | None = None,
    interaction_type: CrossLayerInteractionType = (
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
    ),
    architecture: Architecture = Architecture.ARM,
) -> CrossLayerInteraction:
    if interaction_type is CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE:
        return CrossLayerInteraction.create(
            architecture=architecture,
            interaction_type=interaction_type,
            source_layer=Layer.HARDWARE,
            target_layer=Layer.FIRMWARE,
            initiating_vulnerability_ids=["hardware-vulnerability-A"],
            affected_execution_ids=["affected-execution-A"],
        )
    return CrossLayerInteraction.create(
        architecture=architecture,
        interaction_type=interaction_type,
        source_layer=Layer.DRIVER,
        target_layer=Layer.HARDWARE,
        initiating_vulnerability_ids=(
            ["firmware-vulnerability-A"]
            if interaction_type
            is CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE
            else []
        ),
        target_vulnerability_ids=["hardware-vulnerability-A"],
        trigger_behavior_ids=trigger_ids or ["trigger-A"],
    )


def _fact(
    interaction: CrossLayerInteraction,
    *,
    reference_id: str = "trigger-A",
    event_kind: RuntimeEventKind = RuntimeEventKind.MMIO_WRITE,
) -> DynamicTriggerFact:
    return DynamicTriggerFact.create(
        interaction,
        interaction_reference_id=reference_id,
        event_kind=event_kind,
        program_address="0x10008",
        physical_address="0x40000000",
        access_size=4,
        address_space_id="system-memory",
        memory_map_id="owned-arm-map",
    )


def _binding(
    fact: DynamicTriggerFact,
    *,
    evidence_id: str = "runtime-evidence-A",
    trace_id: str = "runtime-trace-A",
    observation_id: str = "runtime-observation-A",
) -> DynamicTriggerObservationBinding:
    return DynamicTriggerObservationBinding.create(
        fact,
        dynamic_evidence_id=evidence_id,
        runtime_trace_id=trace_id,
        runtime_observation_id=observation_id,
        run_id=f"run-for-{trace_id}",
    )


def _fact_with_updates(
    fact: DynamicTriggerFact, **updates: object
) -> DynamicTriggerFact:
    values = fact.model_dump()
    values.update(updates)
    values["id"] = dynamic_trigger_fact_id(
        interaction_id=str(values["interaction_id"]),
        architecture=values["architecture"],
        interaction_type=values["interaction_type"],
        direction=values["direction"],
        interaction_reference_id=str(values["interaction_reference_id"]),
        reference_role=values["reference_role"],
        event_kind=values["event_kind"],
        program_address=ProgramAddress.model_validate(values["program_address"]),
        physical_address=HardwareAddress.model_validate(values["physical_address"]),
        access_size=int(values["access_size"]),
        address_space_id=values["address_space_id"],
        memory_map_id=values["memory_map_id"],
    )
    return DynamicTriggerFact.model_validate(values)


def _binding_with_updates(
    binding: DynamicTriggerObservationBinding, **updates: object
) -> DynamicTriggerObservationBinding:
    values = binding.model_dump()
    values.update(updates)
    identity = {
        "interaction_id": str(values["interaction_id"]),
        "dynamic_trigger_fact_id": str(values["dynamic_trigger_fact_id"]),
        "dynamic_evidence_id": str(values["dynamic_evidence_id"]),
        "runtime_trace_id": str(values["runtime_trace_id"]),
        "runtime_observation_id": str(values["runtime_observation_id"]),
        "run_id": values["run_id"],
    }
    values["id"] = dynamic_trigger_observation_binding_id(**identity)
    return DynamicTriggerObservationBinding.model_validate(values)


@pytest.mark.parametrize(
    "interaction_type",
    [
        CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
    ],
)
@pytest.mark.parametrize(
    "event_kind",
    [RuntimeEventKind.MMIO_READ, RuntimeEventKind.MMIO_WRITE],
)
def test_valid_type_i_ii_mmio_binding_is_accepted(
    interaction_type: CrossLayerInteractionType,
    event_kind: RuntimeEventKind,
) -> None:
    interaction = _interaction(interaction_type=interaction_type)
    fact = _fact(interaction, event_kind=event_kind)

    validate_dynamic_trigger_bindings(interaction, [fact], [_binding(fact)])


def test_fact_interaction_id_must_match_interaction() -> None:
    interaction = _interaction(trigger_ids=["trigger-A"])
    other = _interaction(trigger_ids=["trigger-A", "trigger-B"])
    fact = _fact(other)

    with pytest.raises(VerificationInputError, match="interaction_id"):
        validate_dynamic_trigger_bindings(interaction, [fact], [])


def test_binding_interaction_id_must_match_interaction() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    binding = _binding_with_updates(
        _binding(fact), interaction_id="different-interaction"
    )

    with pytest.raises(VerificationInputError, match="interaction_id"):
        validate_dynamic_trigger_bindings(interaction, [fact], [binding])


def test_fact_architecture_must_match_interaction() -> None:
    interaction = _interaction(architecture=Architecture.RISC_V)
    arm_fact = _fact(_interaction())
    fact = _fact_with_updates(arm_fact, interaction_id=interaction.id)

    with pytest.raises(VerificationInputError, match="architecture"):
        validate_dynamic_trigger_bindings(interaction, [fact], [])


def test_reference_id_must_exist_in_trigger_behavior_ids() -> None:
    interaction = _interaction()
    fact = _fact_with_updates(
        _fact(interaction), interaction_reference_id="outside-trigger"
    )

    with pytest.raises(VerificationInputError, match="trigger_behavior_ids"):
        validate_dynamic_trigger_bindings(interaction, [fact], [])


def test_reference_role_must_be_trigger_behavior() -> None:
    interaction = _interaction()
    fact = _fact(interaction).model_copy(
        update={
            "reference_role": InteractionReferenceRole.PROPAGATION_BEHAVIOR,
        }
    )

    with pytest.raises(VerificationInputError, match="fact revalidation failed"):
        validate_dynamic_trigger_bindings(interaction, [fact], [])


def test_event_kind_must_be_mmio_read_or_write() -> None:
    interaction = _interaction()
    fact = _fact(interaction).model_copy(
        update={"event_kind": RuntimeEventKind.INSTRUCTION_EXEC}
    )

    with pytest.raises(VerificationInputError, match="fact revalidation failed"):
        validate_dynamic_trigger_bindings(interaction, [fact], [])


def test_type_iii_is_explicitly_rejected_even_without_bindings() -> None:
    interaction = _interaction(
        interaction_type=CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
    )

    with pytest.raises(VerificationInputError, match="Type III.*not implemented"):
        validate_dynamic_trigger_bindings(interaction, [], [])


def test_exact_duplicate_binding_fails_closed() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    binding = _binding(fact)

    with pytest.raises(VerificationInputError, match="binding IDs must be unique"):
        validate_dynamic_trigger_bindings(
            interaction,
            [fact],
            [binding, binding],
        )


def test_duplicate_binding_linkage_with_different_evidence_fails_closed() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    bindings = [
        _binding(fact, evidence_id="runtime-evidence-A"),
        _binding(fact, evidence_id="runtime-evidence-B"),
    ]

    with pytest.raises(VerificationInputError, match="linkage must be unique"):
        validate_dynamic_trigger_bindings(interaction, [fact], bindings)


def test_duplicate_dynamic_evidence_id_fails_closed() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    bindings = [
        _binding(fact),
        _binding(
            fact,
            trace_id="runtime-trace-B",
            observation_id="runtime-observation-B",
        ),
    ]

    with pytest.raises(VerificationInputError, match="Evidence IDs must be unique"):
        validate_dynamic_trigger_bindings(interaction, [fact], bindings)


def test_unknown_fact_binding_fails_closed() -> None:
    interaction = _interaction(trigger_ids=["trigger-A", "trigger-B"])
    first = _fact(interaction, reference_id="trigger-A")
    second = _fact(interaction, reference_id="trigger-B")

    with pytest.raises(VerificationInputError, match="unknown fact"):
        validate_dynamic_trigger_bindings(interaction, [first], [_binding(second)])


def test_one_observation_cannot_bind_conflicting_trigger_facts() -> None:
    interaction = _interaction(trigger_ids=["trigger-A", "trigger-B"])
    first = _fact(interaction, reference_id="trigger-A")
    second = _fact(interaction, reference_id="trigger-B")
    bindings = [
        _binding(first, evidence_id="runtime-evidence-A"),
        _binding(second, evidence_id="runtime-evidence-B"),
    ]

    with pytest.raises(VerificationInputError, match="conflicting trigger facts"):
        validate_dynamic_trigger_bindings(
            interaction,
            [first, second],
            bindings,
        )


def test_multiple_independent_runs_for_one_fact_are_allowed() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    bindings = [
        _binding(fact),
        _binding(
            fact,
            evidence_id="runtime-evidence-B",
            trace_id="runtime-trace-B",
            observation_id="runtime-observation-B",
        ),
    ]

    validate_dynamic_trigger_bindings(interaction, [fact], bindings)


def test_mutated_fact_is_detached_and_revalidated() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    fact.program_address.value = "0x20008"

    with pytest.raises(VerificationInputError, match="fact revalidation failed"):
        validate_dynamic_trigger_bindings(interaction, [fact], [])
