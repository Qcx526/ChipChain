"""Phase 9B0-R1 defenses against post-validation container mutation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from chipchain.models import Architecture
from chipchain.runtime import (
    RuntimeBackendKind,
    RuntimeBackendManifest,
    RuntimeCapability,
    RuntimeCapabilityError,
    RuntimeEventKind,
    RuntimeEvidenceNormalizer,
    RuntimeObservation,
    RuntimeRunMode,
    RuntimeTrace,
    RuntimeTraceManifest,
    revalidate_runtime_trace,
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


def _trace() -> RuntimeTrace:
    backend = RuntimeBackendManifest.create(
        backend_kind=RuntimeBackendKind.OWNED_FIXTURE,
        backend_name="owned-r1-runtime-contract",
        backend_version="1",
        architecture=Architecture.ARM,
        system_emulation=True,
        capabilities=[
            RuntimeCapability.MEMORY_ACCESS,
            RuntimeCapability.PHYSICAL_ADDRESS,
            RuntimeCapability.IO_CLASSIFICATION,
        ],
        metadata=FIXTURE_FLAGS,
    )
    manifest = RuntimeTraceManifest.create(
        run_id="owned-r1-run",
        scenario_id="owned-r1-scenario",
        architecture=Architecture.ARM,
        backend_manifest_id=backend.id,
        run_mode=RuntimeRunMode.TRIGGER,
        artifact_id="owned-r1-runtime-artifact",
        artifact_sha256="b" * 64,
        machine="synthetic-arm-machine",
        cpu="cortex-a9",
        vcpu_count=1,
        metadata=FIXTURE_FLAGS,
    )
    observation = _mmio(manifest.id, sequence_index=1)
    return RuntimeTrace(
        backend_manifest=backend,
        manifest=manifest,
        observations=[observation],
    )


def _mmio(
    trace_id: str,
    *,
    sequence_index: int,
    architecture: Architecture = Architecture.ARM,
    vcpu_index: int = 0,
    event_kind: RuntimeEventKind = RuntimeEventKind.MMIO_WRITE,
) -> RuntimeObservation:
    return RuntimeObservation.create(
        trace_id=trace_id,
        architecture=architecture,
        sequence_index=sequence_index,
        vcpu_index=vcpu_index,
        event_kind=event_kind,
        pc=ProgramAddress(value="0x10008"),
        physical_address=HardwareAddress(value="0x40000000"),
        is_io=True,
        access_size=4,
    )


def _dma(trace_id: str) -> RuntimeObservation:
    return RuntimeObservation.create(
        trace_id=trace_id,
        architecture=Architecture.ARM,
        sequence_index=2,
        vcpu_index=0,
        event_kind=RuntimeEventKind.DMA_WRITE,
        physical_address=HardwareAddress(value="0x80000000"),
        access_size=4,
        device_id="synthetic-dma-device",
    )


def _normalize_original(trace: RuntimeTrace) -> None:
    RuntimeEvidenceNormalizer().normalize(trace.observations[0], trace)


def test_post_validation_appended_unsupported_event_is_rejected() -> None:
    trace = _trace()
    trace.observations.append(_dma(trace.manifest.id))

    with pytest.raises(RuntimeCapabilityError, match="device_dma_observation"):
        _normalize_original(trace)


def test_post_validation_duplicate_sequence_is_rejected() -> None:
    trace = _trace()
    trace.observations.append(
        _mmio(
            trace.manifest.id,
            sequence_index=1,
            event_kind=RuntimeEventKind.MMIO_READ,
        )
    )

    with pytest.raises(ValidationError, match="sequence indexes must be unique"):
        _normalize_original(trace)


def test_post_validation_architecture_mismatch_is_rejected() -> None:
    trace = _trace()
    trace.observations.append(
        _mmio(
            trace.manifest.id,
            sequence_index=2,
            architecture=Architecture.RISC_V,
        )
    )

    with pytest.raises(ValidationError, match="observation architecture mismatch"):
        _normalize_original(trace)


def test_post_validation_vcpu_overflow_is_rejected() -> None:
    trace = _trace()
    trace.observations.append(
        _mmio(trace.manifest.id, sequence_index=2, vcpu_index=1)
    )

    with pytest.raises(ValidationError, match="vCPU index is out of range"):
        _normalize_original(trace)


def test_mutated_backend_capabilities_are_rejected_by_every_upgrade_path() -> None:
    trace = _trace()
    trace.backend_manifest.capabilities.append(
        RuntimeCapability.DEVICE_DMA_OBSERVATION
    )

    for operation in (
        lambda: revalidate_runtime_trace(trace),
        lambda: serialize_runtime_trace(trace),
        lambda: _normalize_original(trace),
    ):
        with pytest.raises(ValidationError, match="Manifest ID is not deterministic"):
            operation()


def test_mutated_fixture_backend_provenance_is_rejected() -> None:
    trace = _trace()
    trace.backend_manifest.metadata.pop("owned")

    with pytest.raises(ValidationError, match="complete synthetic provenance"):
        revalidate_runtime_trace(trace)


def test_valid_trace_revalidation_returns_a_detached_snapshot() -> None:
    trace = _trace()

    snapshot = revalidate_runtime_trace(trace)
    evidence = RuntimeEvidenceNormalizer().normalize(trace.observations[0], trace)
    repeated = RuntimeEvidenceNormalizer().normalize(trace.observations[0], trace)

    assert snapshot == trace
    assert snapshot is not trace
    assert snapshot.backend_manifest is not trace.backend_manifest
    assert snapshot.observations[0] is not trace.observations[0]
    assert evidence == repeated
    assert evidence.verified is True


def test_serialize_and_normalizer_share_fixture_revalidation_contract() -> None:
    trace = _trace()
    trace.manifest.metadata["not_benchmark"] = False

    with pytest.raises(ValidationError, match="complete synthetic provenance"):
        serialize_runtime_trace(trace)
    with pytest.raises(ValidationError, match="complete synthetic provenance"):
        _normalize_original(trace)
