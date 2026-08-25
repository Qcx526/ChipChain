"""Offline safe-runner tests for the isolated Phase 9C observer."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from chipchain.runtime.qemu import (
    QemuArmTriggerSequenceRunConfig,
    QemuTriggerRawTraceError,
    QemuTriggerRunnerError,
    QemuTriggerRunnerTimeoutError,
    QemuTriggerSequenceRunner,
    build_qemu_arm_trigger_sequence_command,
)


ROOT = Path(__file__).resolve().parents[1]
VALID_RAW = (
    ROOT
    / "tests"
    / "fixtures"
    / "qemu_trigger_raw"
    / "valid_arm_a32_trigger_trace.jsonl"
)


def _config(tmp_path: Path) -> QemuArmTriggerSequenceRunConfig:
    tmp_path.mkdir(parents=True, exist_ok=True)
    qemu = tmp_path / "qemu system arm"
    plugin = tmp_path / "trigger observer.so"
    firmware = tmp_path / "owned firmware.elf"
    for path in (qemu, plugin, firmware):
        path.write_bytes(b"owned-phase9c-placeholder")
    return QemuArmTriggerSequenceRunConfig(
        qemu_executable=qemu,
        plugin_path=plugin,
        firmware_elf=firmware,
        raw_trace_path=tmp_path / "trigger raw.jsonl",
        run_id="owned-phase9c-trigger-runtime-run",
        scenario_id="owned-phase9c-trigger-runtime-scenario",
        artifact_id="synthetic-owned-arm-a32-trigger-runtime-elf",
        firmware_sha256=hashlib.sha256(firmware.read_bytes()).hexdigest(),
        timeout_seconds=5,
    )


class _MockProcess:
    def __init__(
        self,
        *,
        raw_source: Path = VALID_RAW,
        timeout: bool = False,
        returncode: int = 0,
        stderr: str = "synthetic failure",
        mutate_firmware: bool = False,
    ) -> None:
        self.raw_source = raw_source
        self.timeout = timeout
        self.returncode = returncode
        self.stderr = stderr
        self.mutate_firmware = mutate_firmware
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
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
        if self.mutate_firmware:
            loader = argv[argv.index("-device") + 1]
            firmware = Path(
                loader.split("loader,file=", 1)[1].rsplit(",cpu-num=0", 1)[0]
            )
            firmware.write_bytes(b"mutated-during-run")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


def test_command_is_fixed_single_vcpu_tcg_argv_without_qmp_or_shell(tmp_path: Path) -> None:
    config = _config(tmp_path)
    argv = build_qemu_arm_trigger_sequence_command(config)

    assert argv[0] == str(config.qemu_executable)
    assert argv[argv.index("-M") + 1] == "virt"
    assert argv[argv.index("-cpu") + 1] == "cortex-a15"
    assert argv[argv.index("-smp") + 1] == "1"
    assert argv[argv.index("-accel") + 1] == "tcg"
    assert "-qmp" not in argv and "-S" not in argv
    assert argv[argv.index("-plugin") + 1].startswith(str(config.plugin_path))


def test_mock_runner_binds_firmware_and_returns_path_neutral_execution_facts(
    tmp_path: Path,
) -> None:
    process = _MockProcess()
    config = _config(tmp_path)
    result = QemuTriggerSequenceRunner(process_runner=process).run(config)

    assert result.qemu_version == "11.0.3"
    assert result.firmware_sha256 == config.firmware_sha256
    assert result.parsed_trace.header.run_id == config.run_id
    assert len(result.runtime_trace.instructions) == 8
    assert result.runtime_trace.instructions[1].instruction_word == "0xe3a00001"
    assert result.runtime_trace.artifact_id == config.artifact_id
    assert result.runtime_trace.metadata == {
        "execution_scope": "declared_arm_a32",
        "observation_scope": "runtime_trigger_sequence_t_only",
    }
    assert all(call[1]["shell"] is False for call in process.calls)
    serialized = result.model_dump_json()
    assert str(tmp_path) not in serialized
    assert "verified" not in serialized
    assert "triggerable" not in serialized


def test_generic_runner_does_not_invent_dataset_provenance(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.artifact_id = "authorized-arm-a32-firmware"

    result = QemuTriggerSequenceRunner(process_runner=_MockProcess()).run(config)

    metadata = result.runtime_trace.metadata
    assert metadata["observation_scope"] == "runtime_trigger_sequence_t_only"
    assert metadata["execution_scope"] == "declared_arm_a32"
    assert {
        "fixture",
        "synthetic",
        "owned",
        "not_benchmark",
        "not_real_vulnerability",
    }.isdisjoint(metadata)


def test_wrong_firmware_hash_rejects_before_qemu_launch(tmp_path: Path) -> None:
    process = _MockProcess()
    config = _config(tmp_path)
    config.firmware_sha256 = "0" * 64
    with pytest.raises(QemuTriggerRunnerError, match="before QEMU launch"):
        QemuTriggerSequenceRunner(process_runner=process).run(config)
    assert process.calls == []


def test_firmware_mutation_timeout_nonzero_and_incomplete_trace_fail_closed(
    tmp_path: Path,
) -> None:
    with pytest.raises(QemuTriggerRunnerError, match="changed during"):
        QemuTriggerSequenceRunner(
            process_runner=_MockProcess(mutate_firmware=True)
        ).run(_config(tmp_path / "mutation"))

    with pytest.raises(QemuTriggerRunnerTimeoutError, match="incomplete"):
        QemuTriggerSequenceRunner(process_runner=_MockProcess(timeout=True)).run(
            _config(tmp_path / "timeout")
        )

    with pytest.raises(QemuTriggerRunnerError, match="exited with code"):
        QemuTriggerSequenceRunner(process_runner=_MockProcess(returncode=3)).run(
            _config(tmp_path / "nonzero")
        )

    incomplete = tmp_path / "missing-end.jsonl"
    incomplete.write_bytes(b"\n".join(VALID_RAW.read_bytes().splitlines()[:-1]) + b"\n")
    with pytest.raises(QemuTriggerRawTraceError):
        QemuTriggerSequenceRunner(
            process_runner=_MockProcess(raw_source=incomplete)
        ).run(_config(tmp_path / "incomplete"))


def test_config_rejects_commas_unsafe_ids_and_noncanonical_hash(tmp_path: Path) -> None:
    values = _config(tmp_path).model_dump()
    values["plugin_path"] = tmp_path / "observer,bad.so"
    with pytest.raises(ValueError, match="commas"):
        QemuArmTriggerSequenceRunConfig.model_validate(values)

    values = _config(tmp_path / "ids").model_dump()
    values["artifact_id"] = "/host/path/firmware.elf"
    with pytest.raises(ValueError, match="path-neutral"):
        QemuArmTriggerSequenceRunConfig.model_validate(values)

    values = _config(tmp_path / "hash").model_dump()
    values["firmware_sha256"] = "A" * 64
    with pytest.raises(ValueError, match="lowercase"):
        QemuArmTriggerSequenceRunConfig.model_validate(values)


def test_nonzero_exit_redacts_secrets_paths_and_bounds_stderr(tmp_path: Path) -> None:
    stderr = (
        "QEMU loader failed; api_key=secret-value "
        "Authorization: BearerSecret password=hunter2 secret=hidden "
        "token=token-value sk-abcdefghijklmnop "
        "/home/example/private/firmware.elf "
        "C:\\Users\\example\\private\\firmware.elf "
        "control=bad\x01value "
        + "diagnostic " * 200
    )

    with pytest.raises(QemuTriggerRunnerError) as captured:
        QemuTriggerSequenceRunner(
            process_runner=_MockProcess(returncode=7, stderr=stderr)
        ).run(_config(tmp_path))

    message = str(captured.value)
    assert "exited with code 7" in message
    assert "QEMU loader failed" in message
    assert "api_key=<redacted>" in message
    assert "authorization=<redacted>" in message.lower()
    assert "<redacted-token>" in message
    assert "<host-path>" in message
    assert "secret-value" not in message
    assert "BearerSecret" not in message
    assert "hunter2" not in message
    assert "token-value" not in message
    assert "sk-abcdefghijklmnop" not in message
    assert "/home/example/private/firmware.elf" not in message
    assert "C:\\Users\\example\\private\\firmware.elf" not in message
    assert "\x01" not in message
    assert len(message) < 900
