"""Offline raw adapter, safe runner, and Dynamic Evidence regressions."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from chipchain.models import EvidenceType, RelationType
from chipchain.runtime import RuntimeCapability, RuntimeEvidenceNormalizer
from chipchain.runtime.qemu import (
    QemuArmPassiveRunConfig,
    QemuExecutableProbeResult,
    QemuPassiveRuntimeRunner,
    QemuRawTraceAdapter,
    QemuRawTraceError,
    QemuRawTraceParser,
    QemuRunnerTimeoutError,
    QemuRunnerError,
    QemuRuntimeProbe,
    build_qemu_arm_passive_command,
)


ROOT = Path(__file__).resolve().parents[1]
VALID_RAW = ROOT / "tests" / "fixtures" / "qemu_raw" / "valid_arm_mmio_trace.jsonl"
MISSING_END = ROOT / "tests" / "fixtures" / "qemu_raw" / "malformed_missing_end.jsonl"


def _config(tmp_path: Path) -> QemuArmPassiveRunConfig:
    qemu = tmp_path / "qemu system arm.exe"
    plugin = tmp_path / "observer plugin.dll"
    firmware = tmp_path / "owned firmware.elf"
    for path in (qemu, plugin, firmware):
        path.write_bytes(b"owned-test-placeholder")
    return QemuArmPassiveRunConfig(
        qemu_executable=qemu,
        plugin_path=plugin,
        firmware_elf=firmware,
        raw_trace_path=tmp_path / "raw trace.jsonl",
        run_id="owned-qemu-mmio-run",
        scenario_id="owned-qemu-mmio-scenario",
        artifact_id="owned-qemu-mmio-raw-v1",
        firmware_sha256=hashlib.sha256(firmware.read_bytes()).hexdigest(),
        timeout_seconds=5,
    )


def _environment(parsed_path: Path = VALID_RAW):
    parsed = QemuRawTraceParser().parse(parsed_path)
    executable = QemuExecutableProbeResult(
        qemu_executable="qemu-system-arm",
        qemu_version="11.0.3",
        probe_method="explicit_path",
    )
    return parsed, QemuRuntimeProbe.combine_plugin_probe(executable, parsed.header)


def test_raw_adapter_constructs_revalidated_runtime_trace(tmp_path: Path) -> None:
    parsed, environment = _environment()
    trace = QemuRawTraceAdapter().build_runtime_trace(
        parsed, environment, _config(tmp_path)
    )

    assert trace.manifest.artifact_sha256 == hashlib.sha256(VALID_RAW.read_bytes()).hexdigest()
    assert trace.manifest.machine == "virt"
    assert trace.manifest.cpu == "cortex-a15"
    assert trace.manifest.vcpu_count == 1
    assert all(
        trace.manifest.metadata[key] is True
        for key in (
            "fixture",
            "synthetic",
            "owned",
            "not_real_vulnerability",
            "not_benchmark",
        )
    )
    assert trace.observations[0].event_kind.value == "instruction_exec"
    mmio = trace.observations[1]
    assert mmio.event_kind.value == "mmio_write"
    assert mmio.pc.value == "0x40200008"
    assert mmio.physical_address.value == "0x9000000"
    assert mmio.is_io is True
    assert mmio.address_space_id is None
    assert mmio.value is None
    assert set(trace.backend_manifest.capabilities) == {
        RuntimeCapability.INSTRUCTION_EXECUTION,
        RuntimeCapability.MEMORY_ACCESS,
        RuntimeCapability.PHYSICAL_ADDRESS,
        RuntimeCapability.IO_CLASSIFICATION,
    }


def test_real_path_dynamic_evidence_remains_interaction_agnostic(tmp_path: Path) -> None:
    parsed, environment = _environment()
    trace = QemuRawTraceAdapter().build_runtime_trace(
        parsed, environment, _config(tmp_path)
    )
    evidence = RuntimeEvidenceNormalizer().normalize(trace.observations[1], trace)

    assert evidence.type is EvidenceType.DYNAMIC_ANALYSIS
    assert evidence.verified is True
    assert evidence.metadata["physical_address"] == "0x9000000"
    assert "interaction_id" not in evidence.metadata
    assert "interaction_reference_id" not in evidence.metadata
    assert "reference_role" not in evidence.metadata


def test_raw_artifact_hash_changes_trace_manifest_identity(tmp_path: Path) -> None:
    copy = tmp_path / "copy.jsonl"
    copy.write_bytes(VALID_RAW.read_bytes().replace(b"\n", b" \n", 1))
    first, first_environment = _environment()
    second, second_environment = _environment(copy)
    config = _config(tmp_path)

    first_trace = QemuRawTraceAdapter().build_runtime_trace(
        first, first_environment, config
    )
    second_trace = QemuRawTraceAdapter().build_runtime_trace(
        second, second_environment, config
    )

    assert first.artifact_sha256 != second.artifact_sha256
    assert first_trace.manifest.id != second_trace.manifest.id


def test_command_builder_preserves_paths_as_argv_without_shell(tmp_path: Path) -> None:
    config = _config(tmp_path)
    argv = build_qemu_arm_passive_command(config)

    assert argv[0] == str(config.qemu_executable)
    assert "-accel" in argv and argv[argv.index("-accel") + 1] == "tcg"
    assert "-smp" in argv and argv[argv.index("-smp") + 1] == "1"
    assert str(config.firmware_elf) in argv[argv.index("-device") + 1]
    assert argv[argv.index("-plugin") + 1].startswith(str(config.plugin_path))


def test_config_rejects_comma_delimited_qemu_option_paths(tmp_path: Path) -> None:
    values = _config(tmp_path).model_dump()
    values["firmware_elf"] = tmp_path / "owned,firmware.elf"

    with pytest.raises(ValueError, match="commas"):
        QemuArmPassiveRunConfig.model_validate(values)


def test_config_requires_path_neutral_raw_artifact_identity(tmp_path: Path) -> None:
    values = _config(tmp_path).model_dump()
    values["artifact_id"] = "C:\\host\\raw.jsonl"

    with pytest.raises(ValueError, match="path-neutral"):
        QemuArmPassiveRunConfig.model_validate(values)


class _MockProcess:
    def __init__(
        self,
        raw_source: Path,
        *,
        timeout: bool = False,
        returncode: int = 0,
        stderr: str = "",
    ) -> None:
        self.raw_source = raw_source
        self.timeout = timeout
        self.returncode = returncode
        self.stderr = stderr
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(
        self, argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, kwargs))
        if argv[-1] == "--version":
            return subprocess.CompletedProcess(
                argv, 0, stdout="QEMU emulator version 11.0.3\n", stderr=""
            )
        if self.timeout:
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 1))
        if self.returncode:
            return subprocess.CompletedProcess(
                argv, self.returncode, stdout="", stderr=self.stderr
            )
        plugin_arg = argv[argv.index("-plugin") + 1]
        output = Path(plugin_arg.split(",out=", 1)[1].rsplit(",run_id=", 1)[0])
        shutil.copyfile(self.raw_source, output)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


def test_mock_runner_builds_complete_runtime_result(tmp_path: Path) -> None:
    process = _MockProcess(VALID_RAW)
    config = _config(tmp_path)
    result = QemuPassiveRuntimeRunner(process_runner=process).run(config)

    assert result.environment.qemu_version == "11.0.3"
    assert len(result.runtime_trace.observations) == 2
    assert all(call[1]["shell"] is False for call in process.calls)


def test_timeout_cannot_produce_dynamic_evidence(tmp_path: Path) -> None:
    process = _MockProcess(VALID_RAW, timeout=True)
    with pytest.raises(QemuRunnerTimeoutError, match="incomplete output"):
        QemuPassiveRuntimeRunner(process_runner=process).run(_config(tmp_path))


def test_incomplete_raw_output_fails_closed(tmp_path: Path) -> None:
    process = _MockProcess(MISSING_END)
    with pytest.raises(QemuRawTraceError):
        QemuPassiveRuntimeRunner(process_runner=process).run(_config(tmp_path))


def test_nonzero_qemu_exit_exposes_bounded_sanitized_stderr(tmp_path: Path) -> None:
    stderr = (
        "QEMU ROM regions overlap at 0x40000000; "
        "firmware=C:\\private\\owned.elf token=super-secret-value "
        + "x" * 1200
    )
    process = _MockProcess(VALID_RAW, returncode=1, stderr=stderr)

    with pytest.raises(QemuRunnerError) as captured:
        QemuPassiveRuntimeRunner(process_runner=process).run(_config(tmp_path))

    message = str(captured.value)
    assert "exited with code 1" in message
    assert "ROM regions overlap at 0x40000000" in message
    assert "<host-path>" in message
    assert "token=<redacted>" in message
    assert "super-secret-value" not in message
    assert len(message) < 900


def test_phase9b1_does_not_change_relation_types() -> None:
    values = {item.value for item in RelationType}
    assert "runtime_mmio" not in values
    assert "executed_at_runtime" not in values
    assert "fault_propagates_to" not in values
