"""Phase 9B2A dynamic trigger fact and observation-binding model tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from chipchain.models import (
    Architecture,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    Layer,
)
from chipchain.runtime import RuntimeEventKind
from chipchain.verification.dynamic_models import (
    DynamicInteractionVerificationInput,
    DynamicTriggerFact,
    DynamicTriggerObservationBinding,
)
from chipchain.verification.enums import (
    InteractionReferenceRole,
    VerificationStatus,
    VerificationSubjectKind,
)
from chipchain.verification.models import VerificationRecord


def _interaction(
    *,
    trigger_ids: list[str] | None = None,
    interaction_type: CrossLayerInteractionType = (
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
    ),
    architecture: Architecture = Architecture.ARM,
) -> CrossLayerInteraction:
    initiating = (
        ["firmware-vulnerability-A"]
        if interaction_type
        is CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE
        else ["hardware-vulnerability-A"]
        if interaction_type
        is CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
        else []
    )
    if interaction_type is CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE:
        return CrossLayerInteraction.create(
            architecture=architecture,
            interaction_type=interaction_type,
            source_layer=Layer.HARDWARE,
            target_layer=Layer.FIRMWARE,
            initiating_vulnerability_ids=initiating,
            affected_execution_ids=["affected-execution-A"],
        )
    return CrossLayerInteraction.create(
        architecture=architecture,
        interaction_type=interaction_type,
        source_layer=Layer.DRIVER,
        target_layer=Layer.HARDWARE,
        initiating_vulnerability_ids=initiating,
        target_vulnerability_ids=["hardware-vulnerability-A"],
        trigger_behavior_ids=trigger_ids or ["trigger-A"],
    )


def _fact(
    interaction: CrossLayerInteraction,
    *,
    reference_id: str = "trigger-A",
    event_kind: RuntimeEventKind = RuntimeEventKind.MMIO_WRITE,
    program_address: str = "0x10008",
    physical_address: str = "0x40000000",
    access_size: int = 4,
    metadata: dict[str, object] | None = None,
) -> DynamicTriggerFact:
    return DynamicTriggerFact.create(
        interaction,
        interaction_reference_id=reference_id,
        event_kind=event_kind,
        program_address=program_address,
        physical_address=physical_address,
        access_size=access_size,
        address_space_id="system-memory",
        memory_map_id="owned-arm-map",
        metadata=metadata,
    )


def _binding(
    fact: DynamicTriggerFact,
    *,
    evidence_id: str = "runtime-evidence-A",
    trace_id: str = "runtime-trace-A",
    observation_id: str = "runtime-observation-A",
    run_id: str = "runtime-run-A",
    metadata: dict[str, object] | None = None,
) -> DynamicTriggerObservationBinding:
    return DynamicTriggerObservationBinding.create(
        fact,
        dynamic_evidence_id=evidence_id,
        runtime_trace_id=trace_id,
        runtime_observation_id=observation_id,
        run_id=run_id,
        metadata=metadata,
    )


def test_dynamic_trigger_fact_identity_is_deterministic_and_metadata_independent() -> None:
    interaction = _interaction()
    first = _fact(interaction, metadata={"order": 1})
    second = _fact(interaction, metadata={"order": 2})

    assert first.id == second.id
    assert first.model_validate_json(first.model_dump_json()) == first


def test_dynamic_trigger_fact_semantic_change_changes_identity() -> None:
    interaction = _interaction()

    assert _fact(interaction, access_size=4).id != _fact(
        interaction, access_size=8
    ).id
    assert _fact(interaction, event_kind=RuntimeEventKind.MMIO_READ).id != _fact(
        interaction, event_kind=RuntimeEventKind.MMIO_WRITE
    ).id


def test_dynamic_trigger_fact_rejects_a_forged_identity() -> None:
    values = _fact(_interaction()).model_dump(mode="json")
    values["id"] = "dynamic-trigger-fact:forged"

    with pytest.raises(ValidationError, match="ID is not deterministic"):
        DynamicTriggerFact.model_validate(values)


def test_fact_create_requires_an_explicit_interaction_trigger_reference() -> None:
    with pytest.raises(ValueError, match="trigger_behavior_ids"):
        _fact(_interaction(), reference_id="outside-interaction")


@pytest.mark.parametrize(
    "field,value",
    [
        ("reference_role", InteractionReferenceRole.TARGET_VULNERABILITY.value),
        ("event_kind", RuntimeEventKind.INSTRUCTION_EXEC.value),
        ("architecture", Architecture.RISC_V.value),
        ("direction", "hardware_to_software"),
    ],
)
def test_fact_contract_rejects_unsupported_scope(field: str, value: object) -> None:
    values = _fact(_interaction()).model_dump(mode="json")
    values[field] = value

    with pytest.raises(ValidationError):
        DynamicTriggerFact.model_validate(values)


def test_fact_create_accepts_type_i_without_creating_a_vulnerability_verdict() -> None:
    interaction = _interaction(
        interaction_type=(
            CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE
        )
    )

    fact = _fact(interaction)

    assert fact.interaction_type is interaction.interaction_type
    assert "verification_status" not in fact.model_dump()
    assert "vulnerability_verdict" not in fact.model_dump()


def test_fact_create_rejects_type_iii_as_not_implemented() -> None:
    interaction = _interaction(
        interaction_type=CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
    )

    with pytest.raises(ValueError, match="Type III.*not implemented"):
        _fact(interaction)


def test_fact_create_rejects_non_arm_interaction() -> None:
    interaction = _interaction(architecture=Architecture.RISC_V)

    with pytest.raises(ValueError, match="only ARM"):
        _fact(interaction)


def test_binding_identity_is_deterministic_and_metadata_independent() -> None:
    fact = _fact(_interaction())
    first = _binding(fact, metadata={"order": 1})
    second = _binding(fact, metadata={"order": 2})

    assert first.id == second.id
    assert first.model_validate_json(first.model_dump_json()) == first


def test_binding_provenance_change_changes_identity() -> None:
    fact = _fact(_interaction())

    assert _binding(fact, trace_id="runtime-trace-A").id != _binding(
        fact, trace_id="runtime-trace-B"
    ).id
    assert _binding(fact, observation_id="observation-A").id != _binding(
        fact, observation_id="observation-B"
    ).id


def test_dynamic_binding_rejects_a_forged_identity() -> None:
    values = _binding(_fact(_interaction())).model_dump(mode="json")
    values["id"] = "dynamic-trigger-binding:forged"

    with pytest.raises(ValidationError, match="ID is not deterministic"):
        DynamicTriggerObservationBinding.model_validate(values)


def test_binding_rejects_a_different_fact_or_interaction() -> None:
    interaction = _interaction(trigger_ids=["trigger-A", "trigger-B"])
    first = _fact(interaction, reference_id="trigger-A")
    second = _fact(interaction, reference_id="trigger-B")

    with pytest.raises(ValueError, match="does not match trigger fact"):
        _binding(first).validate_against(second)


def test_dynamic_input_sorts_models_and_allows_independent_runs() -> None:
    interaction = _interaction(trigger_ids=["trigger-A", "trigger-B"])
    first_fact = _fact(interaction, reference_id="trigger-A")
    second_fact = _fact(interaction, reference_id="trigger-B")
    first_binding = _binding(first_fact)
    second_binding = _binding(
        first_fact,
        evidence_id="runtime-evidence-B",
        trace_id="runtime-trace-B",
        observation_id="runtime-observation-B",
        run_id="runtime-run-B",
    )

    value = DynamicInteractionVerificationInput.create(
        interaction,
        trigger_facts=[second_fact, first_fact],
        observation_bindings=[second_binding, first_binding],
    )

    assert value.trigger_facts == sorted(
        [first_fact, second_fact], key=lambda item: item.id
    )
    assert value.observation_bindings == sorted(
        [first_binding, second_binding], key=lambda item: item.id
    )
    assert value.model_validate_json(value.model_dump_json()) == value


def test_dynamic_input_rejects_duplicate_fact_and_binding_ids() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    binding = _binding(fact)

    with pytest.raises(ValidationError, match="fact IDs must be unique"):
        DynamicInteractionVerificationInput.create(
            interaction,
            trigger_facts=[fact, fact],
        )
    with pytest.raises(ValidationError, match="binding IDs must be unique"):
        DynamicInteractionVerificationInput.create(
            interaction,
            trigger_facts=[fact],
            observation_bindings=[binding, binding],
        )


def test_dynamic_input_rejects_duplicate_observation_linkage() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    bindings = [
        _binding(fact, evidence_id="runtime-evidence-A"),
        _binding(fact, evidence_id="runtime-evidence-B"),
    ]

    with pytest.raises(ValidationError, match="linkage must be unique"):
        DynamicInteractionVerificationInput.create(
            interaction,
            trigger_facts=[fact],
            observation_bindings=bindings,
        )


def test_dynamic_input_rejects_one_observation_bound_to_conflicting_facts() -> None:
    interaction = _interaction(trigger_ids=["trigger-A", "trigger-B"])
    first_fact = _fact(interaction, reference_id="trigger-A")
    second_fact = _fact(interaction, reference_id="trigger-B")
    bindings = [
        _binding(first_fact, evidence_id="runtime-evidence-A"),
        _binding(second_fact, evidence_id="runtime-evidence-B"),
    ]

    with pytest.raises(ValidationError, match="conflicting trigger facts"):
        DynamicInteractionVerificationInput.create(
            interaction,
            trigger_facts=[first_fact, second_fact],
            observation_bindings=bindings,
        )


def test_dynamic_input_rejects_reused_evidence_identity() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    bindings = [
        _binding(fact),
        _binding(
            fact,
            trace_id="runtime-trace-B",
            observation_id="runtime-observation-B",
            run_id="runtime-run-B",
        ),
    ]

    with pytest.raises(ValidationError, match="Evidence IDs must be unique"):
        DynamicInteractionVerificationInput.create(
            interaction,
            trigger_facts=[fact],
            observation_bindings=bindings,
        )


def test_dynamic_input_rejects_unknown_fact_binding() -> None:
    interaction = _interaction(trigger_ids=["trigger-A", "trigger-B"])
    first_fact = _fact(interaction, reference_id="trigger-A")
    second_fact = _fact(interaction, reference_id="trigger-B")

    with pytest.raises(ValidationError, match="unknown fact"):
        DynamicInteractionVerificationInput.create(
            interaction,
            trigger_facts=[first_fact],
            observation_bindings=[_binding(second_fact)],
        )


def test_dynamic_input_rejects_fact_from_a_different_interaction() -> None:
    first_interaction = _interaction(trigger_ids=["trigger-A"])
    second_interaction = _interaction(trigger_ids=["trigger-A", "trigger-B"])

    with pytest.raises(ValidationError, match="identity does not match input"):
        DynamicInteractionVerificationInput.create(
            first_interaction,
            trigger_facts=[_fact(second_interaction)],
        )


def test_dynamic_input_revalidates_a_detached_fact_snapshot() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    fact.program_address.value = "0x20008"

    with pytest.raises(ValidationError, match="ID is not deterministic"):
        DynamicInteractionVerificationInput.create(
            interaction,
            trigger_facts=[fact],
        )


def test_dynamic_verification_record_subject_kind_is_additive() -> None:
    interaction = _interaction()
    binding = _binding(_fact(interaction))

    record = VerificationRecord.create(
        interaction_id=interaction.id,
        architecture=interaction.architecture,
        subject_kind=VerificationSubjectKind.DYNAMIC_TRIGGER_OBSERVATION,
        subject_id=binding.id,
        status=VerificationStatus.UNKNOWN,
        verifier="phase9b2a_dynamic_trigger_observation_v1",
    )

    assert record.subject_kind is VerificationSubjectKind.DYNAMIC_TRIGGER_OBSERVATION
    assert record.id.startswith("verification:dynamic_trigger_observation:")
