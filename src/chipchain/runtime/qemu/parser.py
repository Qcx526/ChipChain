"""Map proven QEMU raw facts into the stable Phase 9B0 RuntimeTrace."""

from __future__ import annotations

import hashlib
import json

from chipchain.models import Architecture
from chipchain.runtime import (
    RuntimeBackendKind,
    RuntimeBackendManifest,
    RuntimeEventKind,
    RuntimeObservation,
    RuntimeRunMode,
    RuntimeTrace,
    RuntimeTraceManifest,
    revalidate_runtime_trace,
)
from chipchain.runtime.qemu.errors import QemuRawTraceError
from chipchain.runtime.qemu.models import (
    QemuArmPassiveRunConfig,
    QemuMemoryTopologySnapshot,
    QemuParsedRawTrace,
    QemuRawEvent,
    QemuRawEventKind,
    QemuRuntimeEnvironment,
)
from chipchain.runtime.qemu.topology import (
    QemuTopologyClassification,
    QemuTopologyClassificationKind,
    QemuTopologyClassifier,
)


def _environment_fingerprint(
    environment: QemuRuntimeEnvironment,
    config: QemuArmPassiveRunConfig,
) -> str:
    payload = {
        "cpu": config.cpu,
        "machine": config.machine,
        "plugin_api_current": environment.plugin_api_current,
        "plugin_api_min": environment.plugin_api_min,
        "qemu_version": environment.qemu_version,
        "smp_vcpus": environment.smp_vcpus,
        "target": "arm",
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class QemuRawTraceAdapter:
    """Construct and revalidate RuntimeTrace without adding security meaning."""

    def __init__(self, classifier: QemuTopologyClassifier | None = None) -> None:
        self._classifier = classifier or QemuTopologyClassifier()

    def build_runtime_trace(
        self,
        parsed: QemuParsedRawTrace,
        environment: QemuRuntimeEnvironment,
        config: QemuArmPassiveRunConfig,
        topology: QemuMemoryTopologySnapshot,
    ) -> RuntimeTrace:
        """Map instructions and promote only topology-classified raw accesses."""

        if parsed.header.run_id != config.run_id:
            raise QemuRawTraceError("QEMU raw run ID does not match runner config")
        if (
            topology.qemu_version != environment.qemu_version
            or topology.machine != config.machine
            or topology.cpu != config.cpu
            or topology.vcpu_count != config.vcpu_count
        ):
            raise QemuRawTraceError(
                "QEMU topology facts do not match the runtime environment"
            )
        backend = RuntimeBackendManifest.create(
            backend_kind=RuntimeBackendKind.QEMU_TCG_PLUGIN,
            backend_name="chipchain-qemu-passive-observer",
            backend_version=environment.qemu_version,
            architecture=Architecture.ARM,
            system_emulation=True,
            capabilities=environment.capabilities,
            metadata={
                "plugin_api_current": environment.plugin_api_current,
                "plugin_api_min": environment.plugin_api_min,
                "plugin_build_api_version": parsed.header.plugin_build_api_version,
                "plugin_name": parsed.header.plugin_name,
                "probe_method": environment.probe_method,
                "target_name": parsed.header.target_name,
                "io_classification_source": "qemu_machine_topology",
            },
        )
        manifest = RuntimeTraceManifest.create(
            run_id=config.run_id,
            scenario_id=config.scenario_id,
            architecture=Architecture.ARM,
            backend_manifest_id=backend.id,
            run_mode=RuntimeRunMode.TRIGGER,
            artifact_id=config.artifact_id,
            artifact_sha256=parsed.artifact_sha256,
            machine=config.machine,
            cpu=config.cpu,
            vcpu_count=config.vcpu_count,
            memory_map_id=topology.id,
            memory_map_sha256=topology.artifact_sha256,
            input_fingerprint=config.firmware_sha256,
            environment_fingerprint=_environment_fingerprint(environment, config),
            metadata={
                "clean_shutdown": parsed.end.clean_shutdown,
                "fixture": True,
                "not_benchmark": True,
                "not_real_vulnerability": True,
                "observer": "qemu_tcg_plugin",
                "owned": True,
                "raw_format": "chipchain_qemu_raw_trace",
                "raw_format_version": 2,
                "topology_capture": "same_process_qmp_before_cont",
                "synthetic": True,
            },
        )
        observations: list[RuntimeObservation] = []
        for item in parsed.events:
            if item.event_kind is QemuRawEventKind.INSTRUCTION_EXEC:
                observations.append(self._instruction_observation(item, manifest.id))
                continue
            classification = self._classifier.classify(item, topology)
            if classification.kind is QemuTopologyClassificationKind.IO:
                observations.append(
                    self._mmio_observation(item, classification, manifest.id)
                )
        return revalidate_runtime_trace(
            RuntimeTrace(
                backend_manifest=backend,
                manifest=manifest,
                observations=observations,
            )
        )

    @staticmethod
    def _instruction_observation(
        event: QemuRawEvent, trace_id: str
    ) -> RuntimeObservation:
        return RuntimeObservation.create(
            trace_id=trace_id,
            architecture=Architecture.ARM,
            sequence_index=event.sequence_index,
            vcpu_index=event.vcpu_index,
            event_kind=RuntimeEventKind.INSTRUCTION_EXEC,
            pc=event.pc,
            value=None,
            value_width_bits=None,
            address_space_id=None,
            metadata={
                "backend_classification": "qemu_plugin_instruction_callback",
                "raw_schema_version": event.schema_version,
            },
        )

    @staticmethod
    def _mmio_observation(
        event: QemuRawEvent,
        classification: QemuTopologyClassification,
        trace_id: str,
    ) -> RuntimeObservation:
        if classification.region is None:
            raise QemuRawTraceError("classified QEMU I/O access has no topology region")
        kind = {
            QemuRawEventKind.MEMORY_READ: RuntimeEventKind.MMIO_READ,
            QemuRawEventKind.MEMORY_WRITE: RuntimeEventKind.MMIO_WRITE,
        }[event.event_kind]
        return RuntimeObservation.create(
            trace_id=trace_id,
            architecture=Architecture.ARM,
            sequence_index=event.sequence_index,
            vcpu_index=event.vcpu_index,
            event_kind=kind,
            pc=event.pc,
            virtual_address=event.virtual_address,
            physical_address=event.physical_address,
            is_io=True,
            access_size=event.access_size,
            value=None,
            value_width_bits=None,
            device_id=None,
            address_space_id=None,
            metadata={
                "classification_source": "qemu_machine_topology",
                "plugin_is_io": event.plugin_is_io,
                "plugin_device_name": event.plugin_device_name,
                "raw_schema_version": event.schema_version,
                "topology_plugin_classification_disagreed": (
                    event.plugin_is_io is False
                ),
                "topology_region_name": classification.region.name,
            },
        )
