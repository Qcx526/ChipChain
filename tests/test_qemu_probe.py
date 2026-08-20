"""Phase 9B1 executable and plugin-runtime probe tests."""

from __future__ import annotations

import subprocess

import pytest
from pydantic import ValidationError

from chipchain.runtime import RuntimeCapability
from chipchain.runtime.qemu import (
    PHASE9B1_PASSIVE_CAPABILITIES,
    QemuExecutableProbeResult,
    QemuProbeError,
    QemuRawHeader,
    QemuRuntimeProbe,
    parse_qemu_version,
)


def _header(**overrides: object) -> QemuRawHeader:
    values: dict[str, object] = {
        "plugin_name": "chipchain-qemu-passive-observer",
        "plugin_build_api_version": 6,
        "target_name": "arm",
        "plugin_api_min": 2,
        "plugin_api_current": 6,
        "system_emulation": True,
        "smp_vcpus": 1,
        "max_vcpus": 1,
        "run_id": "owned-qemu-mmio-run",
    }
    values.update(overrides)
    return QemuRawHeader(**values)


@pytest.mark.parametrize(
    "output,expected",
    [
        ("QEMU emulator version 11.0.3\n", "11.0.3"),
        ("QEMU emulator version 9.2.0 (Debian 1:9.2.0)\n", "9.2.0"),
    ],
)
def test_qemu_version_parser(output: str, expected: str) -> None:
    assert parse_qemu_version(output) == expected


def test_qemu_version_parser_rejects_unrecognized_output() -> None:
    with pytest.raises(QemuProbeError, match="not recognized"):
        parse_qemu_version("not a QEMU version")


def test_executable_probe_uses_safe_argv_and_retains_version() -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def process(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(
            argv, 0, stdout="QEMU emulator version 11.0.3\n", stderr=""
        )

    result = QemuRuntimeProbe(process).probe_executable("qemu-system-arm-custom")

    assert result.qemu_version == "11.0.3"
    assert calls[0][0] == ["qemu-system-arm-custom", "--version"]
    assert calls[0][1]["shell"] is False


def test_plugin_probe_environment_identity_excludes_host_path_and_probe_method() -> None:
    first = QemuExecutableProbeResult(
        qemu_executable="C:/host-a/qemu-system-arm.exe",
        qemu_version="11.0.3",
        probe_method="explicit_path",
    )
    second = QemuExecutableProbeResult(
        qemu_executable="/host-b/qemu-system-arm",
        qemu_version="11.0.3",
        probe_method="environment",
    )

    first_environment = QemuRuntimeProbe.combine_plugin_probe(first, _header())
    second_environment = QemuRuntimeProbe.combine_plugin_probe(second, _header())

    assert first_environment.id == second_environment.id
    assert set(first_environment.capabilities) == PHASE9B1_PASSIVE_CAPABILITIES
    assert RuntimeCapability.MEMORY_VALUE not in first_environment.capabilities
    assert not any("injection" in item.value for item in first_environment.capabilities)


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("target_name", "aarch64", "target must be arm"),
        ("system_emulation", False, "system emulation"),
        ("smp_vcpus", 2, "one vCPU"),
    ],
)
def test_plugin_header_fails_closed_on_unsupported_runtime(
    field: str, value: object, message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        _header(**{field: value})


def test_raw_header_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        _header(qemu_version="11.0.3")


def test_raw_header_rejects_wrong_plugin_or_incompatible_build_api() -> None:
    with pytest.raises(ValidationError):
        _header(plugin_name="not-the-chipchain-observer")
    with pytest.raises(ValidationError, match="outside QEMU's supported range"):
        _header(
            plugin_api_min=2,
            plugin_api_current=3,
            plugin_build_api_version=4,
        )
    with pytest.raises(ValidationError, match="safe identifier"):
        _header(run_id="unsafe,run")
