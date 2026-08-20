"""Safe subprocess runner for the owned Phase 9B1 passive observer."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from pathlib import Path

from chipchain.runtime import revalidate_runtime_trace
from chipchain.runtime.qemu.errors import (
    QemuRunnerError,
    QemuRunnerTimeoutError,
)
from chipchain.runtime.qemu.models import (
    QemuArmPassiveRunConfig,
    QemuPassiveRunResult,
)
from chipchain.runtime.qemu.parser import QemuRawTraceAdapter
from chipchain.runtime.qemu.probe import QemuRuntimeProbe
from chipchain.runtime.qemu.raw import QemuRawTraceParser


ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]
_DIAGNOSTIC_LIMIT = 800
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|authorization|password|secret|token)\s*[:=]\s*\S+"
)
_SECRET_TOKEN = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")
_WINDOWS_PATH = re.compile(r"(?i)\b[A-Z]:[\\/][^\s\"']+")
_POSIX_PATH = re.compile(r"(?<![\w.])/(?:[^/\s]+/)+[^\s\"']*")


def _stderr_diagnostic_summary(stderr: str | None) -> str:
    """Return a bounded diagnostic with common secrets and host paths removed."""

    cleaned = _CONTROL_CHARACTERS.sub(" ", stderr or "")
    cleaned = _SECRET_ASSIGNMENT.sub(r"\1=<redacted>", cleaned)
    cleaned = _SECRET_TOKEN.sub("<redacted-token>", cleaned)
    cleaned = _WINDOWS_PATH.sub("<host-path>", cleaned)
    cleaned = _POSIX_PATH.sub("<host-path>", cleaned)
    cleaned = " ".join(cleaned.split())
    if not cleaned:
        return "stderr unavailable"
    if len(cleaned) > _DIAGNOSTIC_LIMIT:
        return f"{cleaned[: _DIAGNOSTIC_LIMIT - 3]}..."
    return cleaned


def build_qemu_arm_passive_command(config: QemuArmPassiveRunConfig) -> list[str]:
    """Build an argv list; no shell fragments are accepted or returned."""

    plugin_option = (
        f"{config.plugin_path},out={config.raw_trace_path},run_id={config.run_id}"
    )
    return [
        str(config.qemu_executable),
        "-M",
        config.machine,
        "-cpu",
        config.cpu,
        "-smp",
        str(config.vcpu_count),
        "-accel",
        "tcg",
        "-display",
        "none",
        "-serial",
        "null",
        "-monitor",
        "none",
        "-semihosting-config",
        "enable=on,target=native",
        "-device",
        f"loader,file={config.firmware_elf},cpu-num=0",
        "-plugin",
        plugin_option,
    ]


class QemuPassiveRuntimeRunner:
    """Run owned firmware, require a clean raw trace, and return no security verdict."""

    def __init__(
        self,
        *,
        probe: QemuRuntimeProbe | None = None,
        parser: QemuRawTraceParser | None = None,
        adapter: QemuRawTraceAdapter | None = None,
        process_runner: ProcessRunner = subprocess.run,
    ) -> None:
        self._probe = probe or QemuRuntimeProbe(process_runner)
        self._parser = parser or QemuRawTraceParser()
        self._adapter = adapter or QemuRawTraceAdapter()
        self._process_runner = process_runner

    def run(self, config: QemuArmPassiveRunConfig) -> QemuPassiveRunResult:
        """Execute QEMU with a timeout and fail closed on incomplete output."""

        self._require_inputs(config)
        executable = self._probe.probe_executable(str(config.qemu_executable))
        raw_path = config.raw_trace_path.resolve()
        try:
            raw_path.unlink(missing_ok=True)
            completed = self._process_runner(
                build_qemu_arm_passive_command(config),
                check=False,
                capture_output=True,
                text=True,
                shell=False,
                timeout=config.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise QemuRunnerTimeoutError(
                "QEMU timed out; incomplete output cannot become verified Evidence"
            ) from exc
        except OSError as exc:
            raise QemuRunnerError("QEMU passive observer could not be launched") from exc
        if completed.returncode != 0:
            diagnostic = _stderr_diagnostic_summary(completed.stderr)
            raise QemuRunnerError(
                f"QEMU passive observer exited with code {completed.returncode}; "
                f"stderr: {diagnostic}"
            )
        if not raw_path.is_file():
            raise QemuRunnerError("QEMU passive observer produced no raw trace")
        parsed = self._parser.parse(raw_path)
        environment = self._probe.combine_plugin_probe(executable, parsed.header)
        trace = revalidate_runtime_trace(
            self._adapter.build_runtime_trace(parsed, environment, config)
        )
        return QemuPassiveRunResult(
            environment=environment,
            parsed_trace=parsed,
            runtime_trace=trace,
        )

    @staticmethod
    def _require_inputs(config: QemuArmPassiveRunConfig) -> None:
        for label, path in (
            ("QEMU executable", config.qemu_executable),
            ("QEMU plugin", config.plugin_path),
            ("owned firmware ELF", config.firmware_elf),
        ):
            if not Path(path).is_file():
                raise QemuRunnerError(f"{label} does not exist")
        if config.raw_trace_path.exists() and config.raw_trace_path.is_dir():
            raise QemuRunnerError("raw trace output path is a directory")
        config.raw_trace_path.parent.mkdir(parents=True, exist_ok=True)
