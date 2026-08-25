"""Safe isolated runner for the Phase 9C passive trigger observer."""

from __future__ import annotations

import hashlib
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

from chipchain.hardware_trigger import (
    ArmExecutionMode,
    RuntimeInstructionOccurrence,
    RuntimeTriggerExecutionTrace,
)
from chipchain.models import Architecture
from chipchain.runtime.qemu.errors import (
    QemuTriggerRunnerError,
    QemuTriggerRunnerTimeoutError,
)
from chipchain.runtime.qemu.probe import QemuRuntimeProbe
from chipchain.runtime.qemu.trigger_models import (
    QemuArmTriggerSequenceRunConfig,
    QemuParsedTriggerTrace,
    QemuTriggerSequenceRunResult,
)
from chipchain.runtime.qemu.trigger_parser import QemuTriggerRawTraceParser


ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]
_DIAGNOSTIC_LIMIT = 800
_HASH_CHUNK_SIZE = 1024 * 1024
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|authorization|password|secret|token)\s*[:=]\s*\S+"
)
_SECRET_TOKEN = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")
_WINDOWS_PATH = re.compile(r"(?i)\b[A-Z]:[\\/][^\s\"']+")
_POSIX_PATH = re.compile(r"(?<![\w.])/(?:[^/\s]+/)+[^\s\"']*")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(_HASH_CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError as exc:
        raise QemuTriggerRunnerError("firmware ELF could not be hashed") from exc
    return digest.hexdigest()


def _stderr_diagnostic_summary(stderr: str | None) -> str:
    """Return bounded diagnostics without common secrets or absolute paths."""

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


def build_qemu_arm_trigger_sequence_command(
    config: QemuArmTriggerSequenceRunConfig,
) -> list[str]:
    """Build the fixed TCG/single-vCPU argv without invoking a shell."""

    plugin = f"{config.plugin_path},out={config.raw_trace_path},run_id={config.run_id}"
    return [
        str(config.qemu_executable),
        "-M",
        config.machine,
        "-cpu",
        config.cpu,
        "-smp",
        str(config.vcpu_count),
        "-accel",
        config.accelerator,
        "-display",
        "none",
        "-serial",
        "null",
        "-semihosting-config",
        "enable=on,target=native",
        "-device",
        f"loader,file={config.firmware_elf},cpu-num=0",
        "-plugin",
        plugin,
    ]


def _normalize_trigger_trace(
    parsed: QemuParsedTriggerTrace,
    config: QemuArmTriggerSequenceRunConfig,
) -> RuntimeTriggerExecutionTrace:
    instructions: list[RuntimeInstructionOccurrence] = []
    for event in parsed.events:
        pc_value = int(event.pc.value, 16)
        if pc_value > 0xFFFFFFFF:
            raise QemuTriggerRunnerError("runtime instruction PC exceeds ARM32")
        instructions.append(
            RuntimeInstructionOccurrence.create(
                sequence_index=event.sequence_index,
                pc=f"0x{pc_value:08x}",
                instruction_size=event.instruction_size,
                instruction_bytes=event.instruction_bytes,
            )
        )
    return RuntimeTriggerExecutionTrace.create(
        raw_trace_id=parsed.id,
        raw_trace_sha256=parsed.raw_trace_sha256,
        run_id=config.run_id,
        scenario_id=config.scenario_id,
        artifact_id=config.artifact_id,
        artifact_sha256=config.firmware_sha256,
        architecture=Architecture.ARM,
        execution_mode=ArmExecutionMode.A32,
        instructions=instructions,
        metadata={
            "execution_scope": "declared_arm_a32",
            "observation_scope": "runtime_trigger_sequence_t_only",
        },
    )


class QemuTriggerSequenceRunner:
    """Run authorized firmware and return instruction facts without a verdict."""

    def __init__(
        self,
        *,
        probe: QemuRuntimeProbe | None = None,
        parser: QemuTriggerRawTraceParser | None = None,
        process_runner: ProcessRunner = subprocess.run,
    ) -> None:
        self._probe = probe or QemuRuntimeProbe(process_runner)
        self._parser = parser or QemuTriggerRawTraceParser()
        self._process_runner = process_runner

    def run(
        self, config: QemuArmTriggerSequenceRunConfig
    ) -> QemuTriggerSequenceRunResult:
        """Hash before/after, require clean JSONL, and fail closed on timeout."""

        self._require_inputs(config)
        before = _sha256_file(config.firmware_elf)
        if before != config.firmware_sha256:
            raise QemuTriggerRunnerError(
                "firmware SHA-256 mismatch before QEMU launch"
            )
        executable = self._probe.probe_executable(str(config.qemu_executable))
        raw_path = config.raw_trace_path.resolve()
        raw_path.unlink(missing_ok=True)
        try:
            completed = self._process_runner(
                build_qemu_arm_trigger_sequence_command(config),
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                shell=False,
                timeout=config.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise QemuTriggerRunnerTimeoutError(
                "QEMU trigger run timed out; incomplete trace rejected"
            ) from exc
        except OSError as exc:
            raise QemuTriggerRunnerError(
                "QEMU trigger observer could not be launched"
            ) from exc
        if completed.returncode != 0:
            raise QemuTriggerRunnerError(
                f"QEMU trigger observer exited with code {completed.returncode}; "
                f"stderr: {_stderr_diagnostic_summary(completed.stderr)}"
            )
        after = _sha256_file(config.firmware_elf)
        if after != before or after != config.firmware_sha256:
            raise QemuTriggerRunnerError("firmware changed during QEMU trigger run")
        if not raw_path.is_file():
            raise QemuTriggerRunnerError("QEMU trigger observer produced no trace")
        parsed = self._parser.parse(raw_path)
        if parsed.header.run_id != config.run_id:
            raise QemuTriggerRunnerError("trigger raw run ID does not match config")
        runtime_trace = _normalize_trigger_trace(parsed, config)
        return QemuTriggerSequenceRunResult(
            qemu_version=executable.qemu_version,
            run_id=config.run_id,
            scenario_id=config.scenario_id,
            artifact_id=config.artifact_id,
            firmware_sha256=config.firmware_sha256,
            parsed_trace=parsed,
            runtime_trace=runtime_trace,
        )

    @staticmethod
    def _require_inputs(config: QemuArmTriggerSequenceRunConfig) -> None:
        for label, path in (
            ("QEMU executable", config.qemu_executable),
            ("QEMU trigger plugin", config.plugin_path),
            ("firmware ELF", config.firmware_elf),
        ):
            if not path.is_file():
                raise QemuTriggerRunnerError(f"{label} does not exist")
        if config.raw_trace_path.exists() and config.raw_trace_path.is_dir():
            raise QemuTriggerRunnerError("trigger raw output is a directory")
        config.raw_trace_path.parent.mkdir(parents=True, exist_ok=True)
