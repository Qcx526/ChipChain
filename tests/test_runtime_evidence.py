"""Phase 9B0 Dynamic Evidence normalization tests."""

from __future__ import annotations

from chipchain.models import Architecture, EvidenceType, RelationType
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
from chipchain.verification import HardwareAddress, ProgramAddress


def _backend() -> RuntimeBackendManifest:
    return RuntimeBackendManifest.create(
        backend_kind=RuntimeBackendKind.OWNED_FIXTURE,
        backend_name="owned-runtime-contract",
        backend_version="1",
        architecture=Architecture.ARM,
        system_emulation=True,
        capabilities=[
            RuntimeCapability.MEMORY_ACCESS,
            RuntimeCapability.PHYSICAL_ADDRESS,
            RuntimeCapability.IO_CLASSIFICATION,
        ],
        metadata={
            "fixture": True,
            "synthetic": True,
            "owned": True,
            "not_real_vulnerability": True,
            "not_benchmark": True,
        },
    )


def _trace(**overrides: object) -> RuntimeTrace:
    backend = _backend()
    manifest = RuntimeTraceManifest.create(
        run_id="runtime-run-A",
        scenario_id="runtime-scenario-A",
        architecture=Architecture.ARM,
        backend_manifest_id=backend.id,
        run_mode=RuntimeRunMode.TRIGGER,
        artifact_id="owned-runtime-artifact",
        artifact_sha256="a" * 64,
        machine="synthetic-arm-machine",
        cpu="arm926",
        vcpu_count=1,
        metadata={
            "fixture": True,
            "synthetic": True,
            "owned": True,
            "not_real_vulnerability": True,
            "not_benchmark": True,
        },
    )
    values: dict[str, object] = {
        "trace_id": manifest.id,
        "architecture": Architecture.ARM,
        "sequence_index": 1,
        "vcpu_index": 0,
        "event_kind": RuntimeEventKind.MMIO_WRITE,
        "pc": ProgramAddress(value="0x10008"),
        "physical_address": HardwareAddress(value="0x40000000"),
        "is_io": True,
        "access_size": 4,
        "address_space_id": "system-memory",
        "metadata": {"capture_backend_simulated_for_contract": True},
    }
    values.update(overrides)
    observation = RuntimeObservation.create(**values)
    return RuntimeTrace(
        backend_manifest=backend,
        manifest=manifest,
        observations=[observation],
    )


def test_runtime_observation_normalizes_to_deterministic_dynamic_evidence() -> None:
    normalizer = RuntimeEvidenceNormalizer()
    first_trace = _trace()
    second_trace = _trace()
    first = normalizer.normalize(first_trace.observations[0], first_trace)
    second = normalizer.normalize(second_trace.observations[0], second_trace)

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()
    assert first.type is EvidenceType.DYNAMIC_ANALYSIS
    assert first.source == first_trace.backend_manifest.id
    assert first.artifact == first_trace.manifest.id
    assert first.address == "0x10008"


def test_dynamic_evidence_retains_mmio_provenance() -> None:
    trace = _trace()
    evidence = RuntimeEvidenceNormalizer().normalize(trace.observations[0], trace)

    assert evidence.metadata["physical_address"] == "0x40000000"
    assert evidence.metadata["runtime_event_kind"] == "mmio_write"
    assert evidence.metadata["address_space_id"] == "system-memory"


def test_dynamic_evidence_remains_interaction_agnostic() -> None:
    trace = _trace()
    evidence = RuntimeEvidenceNormalizer().normalize(trace.observations[0], trace)

    assert "interaction_reference_id" not in evidence.metadata
    assert "reference_role" not in evidence.metadata
    assert "interaction_id" not in evidence.metadata


def test_fixture_dynamic_evidence_has_complete_boundary_markers() -> None:
    trace = _trace()
    evidence = RuntimeEvidenceNormalizer().normalize(trace.observations[0], trace)

    assert evidence.verified is True
    assert all(
        evidence.metadata[key] is True
        for key in (
            "fixture",
            "synthetic",
            "owned",
            "not_real_vulnerability",
            "not_benchmark",
        )
    )


def test_observation_semantic_change_changes_dynamic_evidence_identity() -> None:
    normalizer = RuntimeEvidenceNormalizer()
    first_trace = _trace(access_size=4)
    second_trace = _trace(access_size=8)
    first = normalizer.normalize(first_trace.observations[0], first_trace)
    second = normalizer.normalize(second_trace.observations[0], second_trace)

    assert first.id != second.id


def test_observation_metadata_order_does_not_change_dynamic_evidence() -> None:
    normalizer = RuntimeEvidenceNormalizer()
    first_trace = _trace(metadata={"a": 1, "b": 2})
    second_trace = _trace(metadata={"b": 2, "a": 1})
    first = normalizer.normalize(first_trace.observations[0], first_trace)
    second = normalizer.normalize(second_trace.observations[0], second_trace)

    assert first == second


def test_normalizer_rejects_an_observation_detached_from_trace() -> None:
    trace = _trace()
    detached = RuntimeObservation.create(
        trace_id=trace.manifest.id,
        architecture=Architecture.ARM,
        sequence_index=2,
        vcpu_index=0,
        event_kind=RuntimeEventKind.MMIO_WRITE,
        pc=ProgramAddress(value="0x1000c"),
        physical_address=HardwareAddress(value="0x40000004"),
        is_io=True,
        access_size=4,
    )

    try:
        RuntimeEvidenceNormalizer().normalize(detached, trace)
    except ValueError as exc:
        assert "validated trace" in str(exc)
    else:
        raise AssertionError("detached observation must not become verified Evidence")


def test_phase9b0_does_not_add_reverse_behavior_relations() -> None:
    relation_values = {item.value for item in RelationType}

    assert "affects_execution" not in relation_values
    assert "fault_propagates_to" not in relation_values
    assert "interrupts_firmware" not in relation_values
    assert "dma_writes_firmware" not in relation_values
