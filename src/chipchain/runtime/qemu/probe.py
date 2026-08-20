"""Two-layer QEMU executable and plugin-runtime capability probe."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping

from chipchain.models import Architecture
from chipchain.runtime import RuntimeCapability
from chipchain.runtime.qemu.errors import QemuProbeError
from chipchain.runtime.qemu.models import (
    PHASE9B1_PASSIVE_CAPABILITIES,
    QemuExecutableProbeResult,
    QemuRawHeader,
    QemuRuntimeEnvironment,
)


_VERSION = re.compile(r"QEMU emulator version\s+([^\s]+)", re.IGNORECASE)
ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]


def parse_qemu_version(output: str) -> str:
    """Extract the executable version without assuming one pinned release."""

    match = _VERSION.search(output)
    if match is None:
        raise QemuProbeError("QEMU executable version output is not recognized")
    return match.group(1)


class QemuRuntimeProbe:
    """Probe the executable first, then combine it with a plugin header."""

    def __init__(self, process_runner: ProcessRunner = subprocess.run) -> None:
        self._process_runner = process_runner

    def probe_executable(
        self,
        executable: str | None = None,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> QemuExecutableProbeResult:
        """Locate and run qemu-system-arm without making plugin claims."""

        env = os.environ if environment is None else environment
        configured = env.get("CHIPCHAIN_QEMU_SYSTEM_ARM")
        if executable is not None:
            candidate, method = executable, "explicit_path"
        elif configured:
            candidate, method = configured, "environment"
        else:
            candidate, method = shutil.which("qemu-system-arm"), "path_lookup"
        if not candidate:
            raise QemuProbeError("qemu-system-arm executable was not found")
        try:
            completed = self._process_runner(
                [candidate, "--version"],
                check=False,
                capture_output=True,
                text=True,
                shell=False,
            )
        except OSError as exc:
            raise QemuProbeError("qemu-system-arm executable could not be launched") from exc
        if completed.returncode != 0:
            raise QemuProbeError("qemu-system-arm --version failed")
        version = parse_qemu_version(completed.stdout or completed.stderr)
        return QemuExecutableProbeResult(
            qemu_executable=candidate,
            qemu_version=version,
            probe_method=method,
        )

    @staticmethod
    def combine_plugin_probe(
        executable: QemuExecutableProbeResult,
        header: QemuRawHeader,
    ) -> QemuRuntimeEnvironment:
        """Create a proven environment only from an actual plugin header."""

        return QemuRuntimeEnvironment.create(
            qemu_executable=executable.qemu_executable,
            qemu_version=executable.qemu_version,
            target_architecture=Architecture.ARM,
            system_emulation=header.system_emulation,
            plugin_supported=True,
            plugin_api_min=header.plugin_api_min,
            plugin_api_current=header.plugin_api_current,
            smp_vcpus=header.smp_vcpus,
            capabilities=list(PHASE9B1_PASSIVE_CAPABILITIES),
            probe_method=f"{executable.probe_method}+qemu_info_t",
            metadata={
                "plugin_build_api_version": header.plugin_build_api_version,
                "plugin_name": header.plugin_name,
                "target_name": header.target_name,
                "max_vcpus": header.max_vcpus,
            },
        )
