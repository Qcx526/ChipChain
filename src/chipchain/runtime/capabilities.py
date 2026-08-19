"""Backend capability checks for validated runtime observations."""

from __future__ import annotations

from collections.abc import Iterable

from chipchain.runtime.enums import RuntimeCapability, RuntimeEventKind
from chipchain.runtime.errors import RuntimeCapabilityError
from chipchain.runtime.models import RuntimeBackendManifest, RuntimeObservation


def validate_runtime_capabilities(
    backend: RuntimeBackendManifest,
    observations: Iterable[RuntimeObservation],
) -> None:
    """Reject observations that the backend did not declare it can capture."""

    available = set(backend.capabilities)
    for observation in observations:
        required = _required_capabilities(observation)
        missing = sorted(required.difference(available), key=lambda item: item.value)
        if missing:
            values = ", ".join(item.value for item in missing)
            raise RuntimeCapabilityError(
                f"backend lacks capabilities for {observation.event_kind.value}: {values}"
            )


def _required_capabilities(
    observation: RuntimeObservation,
) -> set[RuntimeCapability]:
    if observation.event_kind is RuntimeEventKind.INSTRUCTION_EXEC:
        required = {RuntimeCapability.INSTRUCTION_EXECUTION}
    elif observation.event_kind in {RuntimeEventKind.MMIO_READ, RuntimeEventKind.MMIO_WRITE}:
        required = {
            RuntimeCapability.MEMORY_ACCESS,
            RuntimeCapability.PHYSICAL_ADDRESS,
            RuntimeCapability.IO_CLASSIFICATION,
        }
    elif observation.event_kind is RuntimeEventKind.INTERRUPT_DISCONTINUITY:
        required = {RuntimeCapability.INTERRUPT_DISCONTINUITY}
    elif observation.event_kind is RuntimeEventKind.EXCEPTION_DISCONTINUITY:
        required = {RuntimeCapability.EXCEPTION_DISCONTINUITY}
    else:
        required = {RuntimeCapability.DEVICE_DMA_OBSERVATION}
    if observation.value is not None:
        required.add(RuntimeCapability.MEMORY_VALUE)
    return required
