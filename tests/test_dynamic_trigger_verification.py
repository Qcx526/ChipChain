"""Phase 9B2A Dynamic Trigger Observation Verifier tests."""

from __future__ import annotations

import pytest

from chipchain.models import (
    Architecture,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    Evidence,
    Layer,
)
from chipchain.runtime import (
    RuntimeBackendKind,
    RuntimeBackendManifest,
    RuntimeCapability,
    RuntimeEventKind,
    RuntimeEvidenceNormalizer,
    RuntimeObservation,
    RuntimeRunMode,
    RuntimeTrace,
    RuntimeTraceManifest,
)
from chipchain.verification.dynamic import DynamicTriggerObservationVerifier
from chipchain.verification.dynamic_models import (
    DynamicTriggerFact,
    DynamicTriggerObservationBinding,
)
from chipchain.verification.enums import (
    VerificationStatus,
    VerificationSubjectKind,
)
from chipchain.verification.errors import VerificationInputError


def _interaction(
    *,
    interaction_type: CrossLayerInteractionType = (
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
    ),
    trigger_ids: list[str] | None = None,
) -> CrossLayerInteraction:
    if interaction_type is CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE:
        return CrossLayerInteraction.create(
            architecture=Architecture.ARM,
            interaction_type=interaction_type,
            source_layer=Layer.HARDWARE,
            target_layer=Layer.FIRMWARE,
            initiating_vulnerability_ids=["hardware-vulnerability-A"],
            affected_execution_ids=["affected-execution-A"],
        )
    return CrossLayerInteraction.create(
        architecture=Architecture.ARM,
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
    pc: str = "0x10008",
    physical_address: str = "0x40000000",
    access_size: int = 4,
    memory_map_id: str | None = "owned-arm-map",
    address_space_id: str | None = "system-memory",
) -> DynamicTriggerFact:
    return DynamicTriggerFact.create(
        interaction,
        interaction_reference_id=reference_id,
        event_kind=event_kind,
        program_address=pc,
        physical_address=physical_address,
        access_size=access_size,
        memory_map_id=memory_map_id,
        address_space_id=address_space_id,
    )


def _trace(
    *,
    architecture: Architecture = Architecture.ARM,
    event_kind: RuntimeEventKind = RuntimeEventKind.MMIO_WRITE,
    pc: str = "0x10008",
    physical_address: str = "0x40000000",
    access_size: int = 4,
    memory_map_id: str | None = "owned-arm-map",
    address_space_id: str | None = "system-memory",
) -> RuntimeTrace:
    backend = RuntimeBackendManifest.create(
        backend_kind=RuntimeBackendKind.EXTERNAL_TRACE,
        backend_name="phase9b2a-test-observer",
        backend_version="1",
        architecture=architecture,
        system_emulation=True,
        capabilities=[
            RuntimeCapability.MEMORY_ACCESS,
            RuntimeCapability.PHYSICAL_ADDRESS,
            RuntimeCapability.IO_CLASSIFICATION,
        ],
    )
    manifest = RuntimeTraceManifest.create(
        run_id="phase9b2a-run-A",
        scenario_id="phase9b2a-scenario-A",
        architecture=architecture,
        backend_manifest_id=backend.id,
        run_mode=RuntimeRunMode.TRIGGER,
        artifact_id="phase9b2a-runtime-artifact",
        artifact_sha256="a" * 64,
        machine="owned-arm-machine",
        cpu="owned-arm-cpu",
        vcpu_count=1,
        memory_map_id=memory_map_id,
        memory_map_sha256="b" * 64 if memory_map_id is not None else None,
    )
    observation = RuntimeObservation.create(
        trace_id=manifest.id,
        architecture=architecture,
        sequence_index=0,
        vcpu_index=0,
        event_kind=event_kind,
        pc=pc,
        physical_address=physical_address,
        is_io=True,
        access_size=access_size,
        address_space_id=address_space_id,
    )
    return RuntimeTrace(
        backend_manifest=backend,
        manifest=manifest,
        observations=[observation],
    )


def _binding(
    fact: DynamicTriggerFact,
    trace: RuntimeTrace,
    evidence: Evidence,
    *,
    observation_id: str | None = None,
) -> DynamicTriggerObservationBinding:
    return DynamicTriggerObservationBinding.create(
        fact,
        dynamic_evidence_id=evidence.id,
        runtime_trace_id=trace.manifest.id,
        runtime_observation_id=(
            observation_id or trace.observations[0].id
        ),
        run_id=trace.manifest.run_id,
    )


def _evidence(trace: RuntimeTrace) -> Evidence:
    return RuntimeEvidenceNormalizer().normalize(trace.observations[0], trace)


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
def test_exact_runtime_observation_produces_only_verified_dynamic_record(
    interaction_type: CrossLayerInteractionType,
    event_kind: RuntimeEventKind,
) -> None:
    interaction = _interaction(interaction_type=interaction_type)
    fact = _fact(interaction, event_kind=event_kind)
    trace = _trace(event_kind=event_kind)
    evidence = _evidence(trace)
    binding = _binding(fact, trace, evidence)

    record = DynamicTriggerObservationVerifier().verify(
        interaction,
        fact,
        binding,
        trace,
        evidence,
    )

    assert record.subject_kind is VerificationSubjectKind.DYNAMIC_TRIGGER_OBSERVATION
    assert record.subject_id == binding.id
    assert record.verifier == "phase9b2a_dynamic_trigger_observation_v1"
    assert record.status is VerificationStatus.VERIFIED
    assert record.evidence_ids == [evidence.id]
    assert record.supporting_evidence_ids == [evidence.id]
    assert record.messages == ["runtime observation matches explicit trigger fact"]
    assert record.metadata["meaning"] == (
        "runtime_observation_matches_explicit_trigger_fact"
    )
    assert "verification_score" not in record.model_dump()
    assert "interaction_status" not in record.model_dump()


def test_verified_dynamic_record_is_deterministic() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    trace = _trace()
    evidence = _evidence(trace)
    binding = _binding(fact, trace, evidence)
    verifier = DynamicTriggerObservationVerifier()

    assert verifier.verify(interaction, fact, binding, trace, evidence) == (
        verifier.verify(interaction, fact, binding, trace, evidence)
    )


def test_interaction_identity_mismatch_fails_closed() -> None:
    interaction = _interaction(trigger_ids=["trigger-A"])
    other = _interaction(trigger_ids=["trigger-A", "trigger-B"])
    fact = _fact(other)
    trace = _trace()
    evidence = _evidence(trace)

    with pytest.raises(VerificationInputError, match="interaction_id"):
        DynamicTriggerObservationVerifier().verify(
            interaction,
            fact,
            _binding(fact, trace, evidence),
            trace,
            evidence,
        )


def test_illegal_dynamic_trigger_fact_fails_closed() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    fact.program_address.value = "0x20008"
    trace = _trace()
    evidence = _evidence(trace)

    with pytest.raises(VerificationInputError, match="fact revalidation failed"):
        DynamicTriggerObservationVerifier().verify(
            interaction,
            fact,
            _binding(fact, trace, evidence),
            trace,
            evidence,
        )


def test_illegal_binding_fails_closed() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    trace = _trace()
    evidence = _evidence(trace)
    binding = _binding(fact, trace, evidence).model_copy(
        update={"runtime_trace_id": "different-trace"}
    )

    with pytest.raises(VerificationInputError, match="binding revalidation failed"):
        DynamicTriggerObservationVerifier().verify(
            interaction,
            fact,
            binding,
            trace,
            evidence,
        )


def test_type_iii_interaction_is_explicitly_rejected() -> None:
    interaction = _interaction()
    type_iii = _interaction(
        interaction_type=CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
    )
    fact = _fact(interaction)
    trace = _trace()
    evidence = _evidence(trace)

    with pytest.raises(VerificationInputError, match="Type III.*not implemented"):
        DynamicTriggerObservationVerifier().verify(
            type_iii,
            fact,
            _binding(fact, trace, evidence),
            trace,
            evidence,
        )


def test_mutated_runtime_trace_is_detached_and_revalidated() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    trace = _trace()
    evidence = _evidence(trace)
    binding = _binding(fact, trace, evidence)
    trace.observations[0].physical_address.value = "0x40000004"

    with pytest.raises(VerificationInputError, match="RuntimeTrace revalidation failed"):
        DynamicTriggerObservationVerifier().verify(
            interaction,
            fact,
            binding,
            trace,
            evidence,
        )


def test_bound_observation_is_resolved_by_id_from_snapshot() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    trace = _trace()
    evidence = _evidence(trace)
    binding = _binding(
        fact,
        trace,
        evidence,
        observation_id="missing-runtime-observation",
    )

    record = DynamicTriggerObservationVerifier().verify(
        interaction,
        fact,
        binding,
        trace,
        evidence,
    )

    assert record.status is VerificationStatus.UNKNOWN
    assert record.evidence_ids == []
    assert record.supporting_evidence_ids == []


def test_binding_trace_identity_must_match_snapshot() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    trace = _trace()
    evidence = _evidence(trace)
    binding = DynamicTriggerObservationBinding.create(
        fact,
        dynamic_evidence_id=evidence.id,
        runtime_trace_id="different-trace",
        runtime_observation_id=trace.observations[0].id,
        run_id=trace.manifest.run_id,
    )

    with pytest.raises(VerificationInputError, match="runtime_trace_id"):
        DynamicTriggerObservationVerifier().verify(
            interaction,
            fact,
            binding,
            trace,
            evidence,
        )


def test_binding_run_identity_must_match_snapshot() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    trace = _trace()
    evidence = _evidence(trace)
    binding = DynamicTriggerObservationBinding.create(
        fact,
        dynamic_evidence_id=evidence.id,
        runtime_trace_id=trace.manifest.id,
        runtime_observation_id=trace.observations[0].id,
        run_id="different-run",
    )

    with pytest.raises(VerificationInputError, match="run_id"):
        DynamicTriggerObservationVerifier().verify(
            interaction,
            fact,
            binding,
            trace,
            evidence,
        )


def test_input_evidence_must_exactly_equal_regenerated_evidence() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    trace = _trace()
    evidence = _evidence(trace)
    binding = _binding(fact, trace, evidence)
    evidence.metadata["untrusted-extra-field"] = True

    with pytest.raises(VerificationInputError, match="exactly match regenerated"):
        DynamicTriggerObservationVerifier().verify(
            interaction,
            fact,
            binding,
            trace,
            evidence,
        )


@pytest.mark.parametrize(
    "fact_overrides,trace_overrides,conflict_field",
    [
        (
            {"event_kind": RuntimeEventKind.MMIO_READ},
            {"event_kind": RuntimeEventKind.MMIO_WRITE},
            "event_kind",
        ),
        ({"pc": "0x10008"}, {"pc": "0x1000c"}, "PC"),
        (
            {"physical_address": "0x40000000"},
            {"physical_address": "0x40000004"},
            "physical_address",
        ),
        ({"access_size": 4}, {"access_size": 8}, "access_size"),
        (
            {"memory_map_id": "owned-arm-map"},
            {"memory_map_id": "different-arm-map"},
            "memory_map_id",
        ),
        (
            {"address_space_id": "system-memory"},
            {"address_space_id": "different-address-space"},
            "address_space_id",
        ),
    ],
)
def test_explicit_trigger_fact_mismatch_is_rejected(
    fact_overrides: dict[str, object],
    trace_overrides: dict[str, object],
    conflict_field: str,
) -> None:
    interaction = _interaction()
    fact = _fact(interaction, **fact_overrides)
    trace = _trace(**trace_overrides)
    evidence = _evidence(trace)
    binding = _binding(fact, trace, evidence)

    record = DynamicTriggerObservationVerifier().verify(
        interaction,
        fact,
        binding,
        trace,
        evidence,
    )

    assert record.status is VerificationStatus.REJECTED
    assert record.evidence_ids == [evidence.id]
    assert record.supporting_evidence_ids == []
    assert any(conflict_field in message for message in record.messages)


def test_architecture_mismatch_is_rejected_without_cross_architecture_support() -> None:
    interaction = _interaction()
    fact = _fact(interaction)
    trace = _trace(architecture=Architecture.RISC_V)
    evidence = _evidence(trace)
    binding = _binding(fact, trace, evidence)

    record = DynamicTriggerObservationVerifier().verify(
        interaction,
        fact,
        binding,
        trace,
        evidence,
    )

    assert record.status is VerificationStatus.REJECTED
    assert record.supporting_evidence_ids == []
    assert all("architecture" in message for message in record.messages)
