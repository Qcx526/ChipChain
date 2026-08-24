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
_HASH_CHUNK_SIZE = 1024 * 1024
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(_HASH_CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError as exc:
        raise QemuTriggerRunnerError("firmware ELF could not be hashed") from exc
    return digest.hexdigest()


def _bounded_stderr(stderr: str | None) -> str:
    cleaned = " ".join(_CONTROL_CHARACTERS.sub(" ", stderr or "").split())
    return (cleaned[:397] + "...") if len(cleaned) > 400 else (cleaned or "unavailable")


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
            "fixture": True,
            "not_benchmark": True,
            "not_real_vulnerability": True,
            "observation_scope": "runtime_trigger_sequence_t_only",
            "owned": True,
            "synthetic": True,
        },
    )


class QemuTriggerSequenceRunner:
    """Run owned firmware and return instruction facts without a verdict."""

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
                f"stderr: {_bounded_stderr(completed.stderr)}"
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
            ("owned firmware ELF", config.firmware_elf),
        ):
            if not path.is_file():
                raise QemuTriggerRunnerError(f"{label} does not exist")
        if config.raw_trace_path.exists() and config.raw_trace_path.is_dir():
            raise QemuTriggerRunnerError("trigger raw output is a directory")
        config.raw_trace_path.parent.mkdir(parents=True, exist_ok=True)
