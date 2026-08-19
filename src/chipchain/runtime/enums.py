"""Closed enums for the Phase 9B0 runtime evidence contract."""

from enum import Enum


class RuntimeBackendKind(str, Enum):
    """Backend families that may produce a runtime trace."""

    QEMU_TCG_PLUGIN = "qemu_tcg_plugin"
    EXTERNAL_TRACE = "external_trace"
    OWNED_FIXTURE = "owned_fixture"


class RuntimeCapability(str, Enum):
    """A backend's declared observation or intervention capability."""

    INSTRUCTION_EXECUTION = "instruction_execution"
    MEMORY_ACCESS = "memory_access"
    PHYSICAL_ADDRESS = "physical_address"
    IO_CLASSIFICATION = "io_classification"
    MEMORY_VALUE = "memory_value"
    REGISTER_READ = "register_read"
    INTERRUPT_DISCONTINUITY = "interrupt_discontinuity"
    EXCEPTION_DISCONTINUITY = "exception_discontinuity"
    DEVICE_DMA_OBSERVATION = "device_dma_observation"
    ACTIVE_STATE_MUTATION = "active_state_mutation"
    INTERRUPT_INJECTION = "interrupt_injection"
    FAULT_INJECTION = "fault_injection"


PASSIVE_RUNTIME_CAPABILITIES = frozenset(
    {
        RuntimeCapability.INSTRUCTION_EXECUTION,
        RuntimeCapability.MEMORY_ACCESS,
        RuntimeCapability.PHYSICAL_ADDRESS,
        RuntimeCapability.IO_CLASSIFICATION,
        RuntimeCapability.MEMORY_VALUE,
        RuntimeCapability.REGISTER_READ,
        RuntimeCapability.INTERRUPT_DISCONTINUITY,
        RuntimeCapability.EXCEPTION_DISCONTINUITY,
        RuntimeCapability.DEVICE_DMA_OBSERVATION,
    }
)
"""Capabilities that observe execution without intentionally changing it."""


ACTIVE_RUNTIME_CAPABILITIES = frozenset(
    {
        RuntimeCapability.ACTIVE_STATE_MUTATION,
        RuntimeCapability.INTERRUPT_INJECTION,
        RuntimeCapability.FAULT_INJECTION,
    }
)
"""Capabilities that can intentionally alter the controlled runtime."""


class RuntimeRunMode(str, Enum):
    """The experimental role of one runtime execution."""

    BASELINE = "baseline"
    TRIGGER = "trigger"
    INTERVENTION = "intervention"


class RuntimeEventKind(str, Enum):
    """Security-neutral runtime event kinds captured by a backend."""

    INSTRUCTION_EXEC = "instruction_exec"
    MMIO_READ = "mmio_read"
    MMIO_WRITE = "mmio_write"
    INTERRUPT_DISCONTINUITY = "interrupt_discontinuity"
    EXCEPTION_DISCONTINUITY = "exception_discontinuity"
    DMA_READ = "dma_read"
    DMA_WRITE = "dma_write"


class RuntimeInterventionKind(str, Enum):
    """Controlled actions, kept separate from observed runtime events."""

    INTERRUPT_ASSERTION = "interrupt_assertion"
    DMA_WRITE = "dma_write"
    DEVICE_STATE_OVERRIDE = "device_state_override"
    MMIO_RESPONSE_OVERRIDE = "mmio_response_override"
    REGISTER_STATE_OVERRIDE = "register_state_override"
