"""Phase 9B0 runtime identity and event-contract tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from chipchain.models import Architecture
from chipchain.runtime import (
    ACTIVE_RUNTIME_CAPABILITIES,
    PASSIVE_RUNTIME_CAPABILITIES,
    RuntimeBackendKind,
    RuntimeBackendManifest,
    RuntimeCapability,
    RuntimeEventKind,
    RuntimeIntervention,
    RuntimeInterventionKind,
    RuntimeObservation,
)
from chipchain.verification import HardwareAddress, ProgramAddress


FIXTURE_FLAGS = {
    "fixture": True,
    "synthetic": True,
    "owned": True,
    "not_real_vulnerability": True,
    "not_benchmark": True,
}


def _backend(**overrides: object) -> RuntimeBackendManifest:
    values: dict[str, object] = {
        "backend_kind": RuntimeBackendKind.OWNED_FIXTURE,
        "backend_name": "owned-runtime-contract",
        "backend_version": "1",
        "architecture": Architecture.ARM,
        "system_emulation": True,
        "capabilities": [
            RuntimeCapability.PHYSICAL_ADDRESS,
            RuntimeCapability.MEMORY_ACCESS,
            RuntimeCapability.IO_CLASSIFICATION,
        ],
        "metadata": FIXTURE_FLAGS,
    }
    values.update(overrides)
    return RuntimeBackendManifest.create(**values)


def _instruction(**overrides: object) -> RuntimeObservation:
    values: dict[str, object] = {
        "trace_id": "trace-A",
        "architecture": Architecture.ARM,
        "sequence_index": 0,
        "vcpu_index": 0,
        "event_kind": RuntimeEventKind.INSTRUCTION_EXEC,
        "pc": ProgramAddress(value="0x10008"),
    }
    values.update(overrides)
    return RuntimeObservation.create(**values)


def _mmio(**overrides: object) -> RuntimeObservation:
    values: dict[str, object] = {
        "trace_id": "trace-A",
        "architecture": Architecture.ARM,
        "sequence_index": 1,
        "vcpu_index": 0,
        "event_kind": RuntimeEventKind.MMIO_WRITE,
        "pc": ProgramAddress(value="0x10008"),
        "physical_address": HardwareAddress(value="0x40000000"),
        "is_io": True,
        "access_size": 4,
    }
    values.update(overrides)
    return RuntimeObservation.create(**values)


def test_backend_manifest_identity_is_deterministic_and_metadata_independent() -> None:
    first = _backend(metadata={**FIXTURE_FLAGS, "order": 1})
    second = _backend(metadata={**FIXTURE_FLAGS, "order": 2})

    assert first.id == second.id


def test_backend_version_is_retained_and_changes_identity() -> None:
    first = _backend(backend_version="8.2.0")
    second = _backend(backend_version="9.1.0")

    assert first.backend_version == "8.2.0"
    assert first.id != second.id


def test_capabilities_are_unique_and_sorted() -> None:
    backend = _backend()

    assert backend.capabilities == sorted(backend.capabilities, key=lambda item: item.value)
    with pytest.raises(ValidationError, match="capabilities must be unique"):
        _backend(
            capabilities=[
                RuntimeCapability.MEMORY_ACCESS,
                RuntimeCapability.MEMORY_ACCESS,
            ]
        )


def test_passive_and_active_capabilities_are_disjoint() -> None:
    assert PASSIVE_RUNTIME_CAPABILITIES.isdisjoint(ACTIVE_RUNTIME_CAPABILITIES)
    assert RuntimeCapability.FAULT_INJECTION in ACTIVE_RUNTIME_CAPABILITIES


def test_runtime_observation_identity_is_deterministic() -> None:
    assert _mmio().id == _mmio().id


def test_metadata_and_host_timestamp_do_not_change_observation_identity() -> None:
    first = _mmio(
        metadata={"a": 1, "b": 2},
        host_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    second = _mmio(
        metadata={"b": 2, "a": 1},
        host_timestamp=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )

    assert first.id == second.id


def test_semantic_event_change_changes_observation_identity() -> None:
    assert _mmio(access_size=4).id != _mmio(access_size=8).id


def test_naive_host_timestamp_is_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone"):
        _instruction(host_timestamp=datetime(2026, 1, 1))


@pytest.mark.parametrize("missing", ["physical_address", "pc", "access_size"])
def test_mmio_requires_address_pc_and_size(missing: str) -> None:
    with pytest.raises(ValidationError, match="MMIO observation requires"):
        _mmio(**{missing: None})


def test_mmio_requires_io_classification_true() -> None:
    with pytest.raises(ValidationError, match="is_io=true"):
        _mmio(is_io=False)


def test_runtime_value_requires_width_and_must_fit() -> None:
    with pytest.raises(ValidationError, match="requires value_width_bits"):
        _mmio(value=1)
    with pytest.raises(ValidationError, match="does not fit"):
        _mmio(value=256, value_width_bits=8)
    with pytest.raises(ValidationError, match="width must match access size"):
        _mmio(value=1, value_width_bits=16)


def test_instruction_execution_requires_pc() -> None:
    with pytest.raises(ValidationError, match="requires PC"):
        _instruction(pc=None)


@pytest.mark.parametrize(
    "event_kind",
    [
        RuntimeEventKind.INTERRUPT_DISCONTINUITY,
        RuntimeEventKind.EXCEPTION_DISCONTINUITY,
    ],
)
def test_discontinuity_requires_from_and_to_pc(event_kind: RuntimeEventKind) -> None:
    with pytest.raises(ValidationError, match="requires from_pc and to_pc"):
        RuntimeObservation.create(
            trace_id="trace-A",
            architecture=Architecture.ARM,
            sequence_index=0,
            vcpu_index=0,
            event_kind=event_kind,
            from_pc=ProgramAddress(value="0x10008"),
        )


@pytest.mark.parametrize(
    "event_kind", [RuntimeEventKind.DMA_READ, RuntimeEventKind.DMA_WRITE]
)
def test_dma_requires_device_address_and_size(event_kind: RuntimeEventKind) -> None:
    with pytest.raises(ValidationError, match="DMA observation requires"):
        RuntimeObservation.create(
            trace_id="trace-A",
            architecture=Architecture.ARM,
            sequence_index=0,
            vcpu_index=0,
            event_kind=event_kind,
            physical_address=HardwareAddress(value="0x80000000"),
            access_size=4,
        )


def test_intervention_is_a_distinct_deterministic_contract() -> None:
    metadata = {
        "fixture": True,
        "synthetic": True,
        "owned": True,
        "not_real_vulnerability": True,
        "not_benchmark": True,
    }
    values = {
        "run_id": "intervention-run",
        "scenario_id": "type3-contract",
        "architecture": Architecture.ARM,
        "intervention_kind": RuntimeInterventionKind.DEVICE_STATE_OVERRIDE,
        "controller_backend": "owned-controller",
        "target_device_id": "synthetic-device",
        "before_sequence_index": 1,
        "metadata": metadata,
    }
    first = RuntimeIntervention.create(**values)
    second = RuntimeIntervention.create(**values)

    assert first.id == second.id
    assert not isinstance(first, RuntimeObservation)


def test_fixture_intervention_requires_complete_provenance() -> None:
    with pytest.raises(ValidationError, match="complete synthetic provenance"):
        RuntimeIntervention.create(
            run_id="run",
            scenario_id="scenario",
            architecture=Architecture.ARM,
            intervention_kind=RuntimeInterventionKind.INTERRUPT_ASSERTION,
            controller_backend="owned-controller",
            metadata={"fixture": True},
        )
