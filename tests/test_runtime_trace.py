"""Phase 9B0 trace integrity, capability, and persistence tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.models import Architecture
from chipchain.runtime import (
    RuntimeBackendKind,
    RuntimeBackendManifest,
    RuntimeCapability,
    RuntimeCapabilityError,
    RuntimeEventKind,
    RuntimeObservation,
    RuntimePersistenceError,
    RuntimeRunMode,
    RuntimeTrace,
    RuntimeTraceManifest,
    load_runtime_trace,
    save_runtime_trace,
    serialize_runtime_trace,
)
from chipchain.verification import HardwareAddress, ProgramAddress


FIXTURE_FLAGS = {
    "fixture": True,
    "synthetic": True,
    "owned": True,
    "not_real_vulnerability": True,
    "not_benchmark": True,
}


def _backend(capabilities: list[RuntimeCapability]) -> RuntimeBackendManifest:
    return RuntimeBackendManifest.create(
        backend_kind=RuntimeBackendKind.OWNED_FIXTURE,
        backend_name="owned-runtime-contract",
        backend_version="1",
        architecture=Architecture.ARM,
        system_emulation=True,
        capabilities=capabilities,
        metadata=FIXTURE_FLAGS,
    )


def _manifest(backend: RuntimeBackendManifest, **overrides: object) -> RuntimeTraceManifest:
    values: dict[str, object] = {
        "run_id": "owned-run",
        "scenario_id": "owned-scenario",
        "architecture": Architecture.ARM,
        "backend_manifest_id": backend.id,
        "run_mode": RuntimeRunMode.TRIGGER,
        "artifact_id": "owned-runtime-trace.jsonl",
        "artifact_sha256": "a" * 64,
        "machine": "synthetic-arm-machine",
        "cpu": "cortex-a9",
        "vcpu_count": 1,
        "metadata": FIXTURE_FLAGS,
    }
    values.update(overrides)
    return RuntimeTraceManifest.create(**values)


def _mmio(trace_id: str, **overrides: object) -> RuntimeObservation:
    values: dict[str, object] = {
        "trace_id": trace_id,
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


def _trace(
    capabilities: list[RuntimeCapability] | None = None,
    observations: list[RuntimeObservation] | None = None,
) -> RuntimeTrace:
    backend = _backend(
        capabilities
        or [
            RuntimeCapability.MEMORY_ACCESS,
            RuntimeCapability.PHYSICAL_ADDRESS,
            RuntimeCapability.IO_CLASSIFICATION,
        ]
    )
    manifest = _manifest(backend)
    return RuntimeTrace(
        backend_manifest=backend,
        manifest=manifest,
        observations=observations or [_mmio(manifest.id)],
    )


def test_trace_manifest_identity_is_metadata_independent() -> None:
    backend = _backend([])
    assert _manifest(backend, metadata={**FIXTURE_FLAGS, "a": 1}).id == _manifest(
        backend, metadata={**FIXTURE_FLAGS, "a": 2}
    ).id


def test_trace_rejects_backend_and_observation_architecture_mismatch() -> None:
    backend = _backend([])
    manifest = _manifest(backend)
    observation = RuntimeObservation.create(
        trace_id=manifest.id,
        architecture=Architecture.RISC_V,
        sequence_index=0,
        vcpu_index=0,
        event_kind=RuntimeEventKind.INSTRUCTION_EXEC,
        pc=ProgramAddress(value="0x1000"),
    )
    with pytest.raises(ValidationError, match="observation architecture mismatch"):
        RuntimeTrace(
            backend_manifest=backend,
            manifest=manifest,
            observations=[observation],
        )


def test_trace_rejects_duplicate_observation_ids() -> None:
    trace = _trace()
    with pytest.raises(ValidationError, match="observation IDs must be unique"):
        RuntimeTrace(
            backend_manifest=trace.backend_manifest,
            manifest=trace.manifest,
            observations=[trace.observations[0], trace.observations[0]],
        )


def test_trace_rejects_duplicate_sequence_indexes() -> None:
    trace = _trace()
    second = _mmio(
        trace.manifest.id,
        event_kind=RuntimeEventKind.MMIO_READ,
        sequence_index=1,
    )
    with pytest.raises(ValidationError, match="sequence indexes must be unique"):
        RuntimeTrace(
            backend_manifest=trace.backend_manifest,
            manifest=trace.manifest,
            observations=[trace.observations[0], second],
        )


def test_trace_sorts_observations_by_sequence_index() -> None:
    backend = _backend(
        [
            RuntimeCapability.INSTRUCTION_EXECUTION,
            RuntimeCapability.MEMORY_ACCESS,
            RuntimeCapability.PHYSICAL_ADDRESS,
            RuntimeCapability.IO_CLASSIFICATION,
        ]
    )
    manifest = _manifest(backend)
    instruction = RuntimeObservation.create(
        trace_id=manifest.id,
        architecture=Architecture.ARM,
        sequence_index=0,
        vcpu_index=0,
        event_kind=RuntimeEventKind.INSTRUCTION_EXEC,
        pc=ProgramAddress(value="0x10008"),
    )
    trace = RuntimeTrace(
        backend_manifest=backend,
        manifest=manifest,
        observations=[_mmio(manifest.id), instruction],
    )

    assert [item.sequence_index for item in trace.observations] == [0, 1]


@pytest.mark.parametrize(
    "event_kind,capability,fields",
    [
        (
            RuntimeEventKind.INTERRUPT_DISCONTINUITY,
            RuntimeCapability.INTERRUPT_DISCONTINUITY,
            {"from_pc": ProgramAddress(value="0x1000"), "to_pc": ProgramAddress(value="0x2000")},
        ),
        (
            RuntimeEventKind.EXCEPTION_DISCONTINUITY,
            RuntimeCapability.EXCEPTION_DISCONTINUITY,
            {"from_pc": ProgramAddress(value="0x1000"), "to_pc": ProgramAddress(value="0x2000")},
        ),
        (
            RuntimeEventKind.DMA_WRITE,
            RuntimeCapability.DEVICE_DMA_OBSERVATION,
            {
                "physical_address": HardwareAddress(value="0x80000000"),
                "access_size": 4,
                "device_id": "synthetic-dma-device",
            },
        ),
    ],
)
def test_event_requires_declared_backend_capability(
    event_kind: RuntimeEventKind,
    capability: RuntimeCapability,
    fields: dict[str, object],
) -> None:
    backend = _backend([])
    manifest = _manifest(backend)
    observation = RuntimeObservation.create(
        trace_id=manifest.id,
        architecture=Architecture.ARM,
        sequence_index=0,
        vcpu_index=0,
        event_kind=event_kind,
        **fields,
    )
    with pytest.raises(RuntimeCapabilityError, match=capability.value):
        RuntimeTrace(
            backend_manifest=backend,
            manifest=manifest,
            observations=[observation],
        )


def test_mmio_requires_declared_passive_capability_set() -> None:
    backend = _backend([RuntimeCapability.MEMORY_ACCESS])
    manifest = _manifest(backend)
    with pytest.raises(RuntimeCapabilityError, match="physical_address"):
        RuntimeTrace(
            backend_manifest=backend,
            manifest=manifest,
            observations=[_mmio(manifest.id)],
        )


def test_mmio_value_requires_memory_value_capability() -> None:
    backend = _backend(
        [
            RuntimeCapability.MEMORY_ACCESS,
            RuntimeCapability.PHYSICAL_ADDRESS,
            RuntimeCapability.IO_CLASSIFICATION,
        ]
    )
    manifest = _manifest(backend)
    observation = _mmio(manifest.id, value=1, value_width_bits=32)
    with pytest.raises(RuntimeCapabilityError, match="memory_value"):
        RuntimeTrace(
            backend_manifest=backend,
            manifest=manifest,
            observations=[observation],
        )


def test_trace_json_round_trip_and_deterministic_persistence(tmp_path: Path) -> None:
    trace = _trace()
    destination = tmp_path / "trace.json"
    save_runtime_trace(trace, destination)

    restored = load_runtime_trace(destination)

    assert restored == trace
    assert destination.read_text(encoding="utf-8") == serialize_runtime_trace(trace)


def test_invalid_persisted_trace_is_rejected(tmp_path: Path) -> None:
    values = _trace().model_dump(mode="json")
    values["observations"][0]["physical_address"]["value"] = "0x40000004"
    source = tmp_path / "invalid.json"
    source.write_text(json.dumps(values), encoding="utf-8")

    with pytest.raises(RuntimePersistenceError):
        load_runtime_trace(source)
