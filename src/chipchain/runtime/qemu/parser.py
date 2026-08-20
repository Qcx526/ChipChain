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
    QemuParsedRawTrace,
    QemuRawEvent,
    QemuRawEventKind,
    QemuRuntimeEnvironment,
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

    def build_runtime_trace(
        self,
        parsed: QemuParsedRawTrace,
        environment: QemuRuntimeEnvironment,
        config: QemuArmPassiveRunConfig,
    ) -> RuntimeTrace:
        """Map instruction/MMIO records and preserve raw artifact provenance."""

        if parsed.header.run_id != config.run_id:
            raise QemuRawTraceError("QEMU raw run ID does not match runner config")
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
                "raw_format_version": 1,
                "synthetic": True,
            },
        )
        observations = [self._observation(item, manifest.id) for item in parsed.events]
        return revalidate_runtime_trace(
            RuntimeTrace(
                backend_manifest=backend,
                manifest=manifest,
                observations=observations,
            )
        )

    @staticmethod
    def _observation(event: QemuRawEvent, trace_id: str) -> RuntimeObservation:
        kind = {
            QemuRawEventKind.INSTRUCTION_EXEC: RuntimeEventKind.INSTRUCTION_EXEC,
            QemuRawEventKind.MMIO_READ: RuntimeEventKind.MMIO_READ,
            QemuRawEventKind.MMIO_WRITE: RuntimeEventKind.MMIO_WRITE,
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
            is_io=event.is_io,
            access_size=event.access_size,
            value=None,
            value_width_bits=None,
            address_space_id=None,
            metadata={
                "backend_classification": "qemu_plugin_hwaddr_is_io"
                if kind in {RuntimeEventKind.MMIO_READ, RuntimeEventKind.MMIO_WRITE}
                else "qemu_plugin_instruction_callback",
                "raw_schema_version": event.schema_version,
            },
        )
