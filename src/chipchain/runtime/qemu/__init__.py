"""Public Phase 9B1 ARM QEMU passive observer API."""

from chipchain.runtime.qemu.errors import (
    QemuProbeError,
    QemuQmpError,
    QemuRawTraceError,
    QemuRunnerError,
    QemuRunnerTimeoutError,
    QemuRuntimeError,
    QemuTopologyClassificationError,
    QemuTopologyError,
    QemuTriggerRawTraceError,
    QemuTriggerRunnerError,
    QemuTriggerRunnerTimeoutError,
)
from chipchain.runtime.qemu.models import (
    PHASE9B1_PASSIVE_CAPABILITIES,
    QemuArmPassiveRunConfig,
    QemuExecutableProbeResult,
    QemuMemoryRegion,
    QemuMemoryRegionKind,
    QemuMemoryTopologySnapshot,
    QemuParsedRawTrace,
    QemuPassiveRunResult,
    QemuRawEnd,
    QemuRawEvent,
    QemuRawEventKind,
    QemuRawHeader,
    QemuRuntimeEnvironment,
    qemu_memory_topology_id,
    qemu_runtime_environment_id,
)
from chipchain.runtime.qemu.parser import QemuRawTraceAdapter
from chipchain.runtime.qemu.probe import QemuRuntimeProbe, parse_qemu_version
from chipchain.runtime.qemu.raw import QemuRawTraceParser
from chipchain.runtime.qemu.qmp import (
    build_qmp_command_stream,
    parse_qmp_topology_response,
)
from chipchain.runtime.qemu.runner import (
    QemuPassiveRuntimeRunner,
    build_qemu_arm_passive_command,
)
from chipchain.runtime.qemu.topology import (
    QemuMemoryTopologyParser,
    QemuTopologyClassification,
    QemuTopologyClassificationKind,
    QemuTopologyClassifier,
)
from chipchain.runtime.qemu.trigger_models import (
    QemuArmTriggerSequenceRunConfig,
    QemuParsedTriggerTrace,
    QemuTriggerRawEnd,
    QemuTriggerRawHeader,
    QemuTriggerRawInstructionEvent,
    QemuTriggerSequenceRunResult,
    qemu_parsed_trigger_trace_id,
)
from chipchain.runtime.qemu.trigger_parser import QemuTriggerRawTraceParser
from chipchain.runtime.qemu.trigger_runner import (
    QemuTriggerSequenceRunner,
    build_qemu_arm_trigger_sequence_command,
)

__all__ = [
    "PHASE9B1_PASSIVE_CAPABILITIES",
    "QemuArmPassiveRunConfig",
    "QemuExecutableProbeResult",
    "QemuMemoryRegion",
    "QemuMemoryRegionKind",
    "QemuMemoryTopologyParser",
    "QemuMemoryTopologySnapshot",
    "QemuParsedRawTrace",
    "QemuPassiveRunResult",
    "QemuPassiveRuntimeRunner",
    "QemuProbeError",
    "QemuQmpError",
    "QemuRawEnd",
    "QemuRawEvent",
    "QemuRawEventKind",
    "QemuRawHeader",
    "QemuRawTraceAdapter",
    "QemuRawTraceError",
    "QemuRawTraceParser",
    "QemuRunnerError",
    "QemuRunnerTimeoutError",
    "QemuRuntimeEnvironment",
    "QemuRuntimeError",
    "QemuTopologyClassification",
    "QemuTopologyClassificationError",
    "QemuTopologyClassificationKind",
    "QemuTopologyClassifier",
    "QemuTopologyError",
    "QemuArmTriggerSequenceRunConfig",
    "QemuParsedTriggerTrace",
    "QemuTriggerRawEnd",
    "QemuTriggerRawHeader",
    "QemuTriggerRawInstructionEvent",
    "QemuTriggerRawTraceError",
    "QemuTriggerRawTraceParser",
    "QemuTriggerRunnerError",
    "QemuTriggerRunnerTimeoutError",
    "QemuTriggerSequenceRunResult",
    "QemuTriggerSequenceRunner",
    "build_qemu_arm_trigger_sequence_command",
    "build_qemu_arm_passive_command",
    "build_qmp_command_stream",
    "parse_qemu_version",
    "parse_qmp_topology_response",
    "qemu_memory_topology_id",
    "qemu_runtime_environment_id",
    "qemu_parsed_trigger_trace_id",
]
