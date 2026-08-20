"""Opt-in real QEMU integration for the owned Phase 9B1 fixture."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from chipchain.runtime import RuntimeEvidenceNormalizer, RuntimeEventKind
from chipchain.runtime.qemu import QemuArmPassiveRunConfig, QemuPassiveRuntimeRunner


pytestmark = pytest.mark.qemu
ROOT = Path(__file__).resolve().parents[1]


def _plugin_default() -> Path:
    suffix = ".dll" if os.name == "nt" else ".dylib" if sys.platform == "darwin" else ".so"
    return ROOT / "tools" / "qemu_plugins" / f"chipchain_runtime_observer{suffix}"


def test_real_owned_arm_qemu_observation_to_dynamic_evidence() -> None:
    if os.environ.get("CHIPCHAIN_RUN_QEMU_TESTS") != "1":
        pytest.skip("set CHIPCHAIN_RUN_QEMU_TESTS=1 for real QEMU validation")
    qemu_value = os.environ.get("CHIPCHAIN_QEMU_SYSTEM_ARM") or shutil.which(
        "qemu-system-arm"
    )
    plugin = Path(os.environ.get("CHIPCHAIN_QEMU_PLUGIN", _plugin_default()))
    if not qemu_value:
        pytest.fail("CHIPCHAIN_RUN_QEMU_TESTS=1 but qemu-system-arm is unavailable")
    qemu = Path(qemu_value)
    if not qemu.is_file() or not plugin.is_file():
        pytest.fail("real QEMU executable or compiled observer plugin is unavailable")
    firmware = ROOT / "tests" / "fixtures" / "qemu_arm_baremetal" / "arm_qemu_mmio.elf"
    with tempfile.TemporaryDirectory(prefix="chipchain-qemu-test-") as directory:
        config = QemuArmPassiveRunConfig(
            qemu_executable=qemu,
            plugin_path=plugin,
            firmware_elf=firmware,
            raw_trace_path=Path(directory) / "raw.jsonl",
            run_id="owned-qemu-mmio-run",
            scenario_id="owned-qemu-mmio-scenario",
            artifact_id="owned-qemu-mmio-raw-v1",
            firmware_sha256=hashlib.sha256(firmware.read_bytes()).hexdigest(),
        )
        result = QemuPassiveRuntimeRunner().run(config)
    assert any(
        item.event_kind is RuntimeEventKind.INSTRUCTION_EXEC
        for item in result.runtime_trace.observations
    )
    mmio = next(
        item
        for item in result.runtime_trace.observations
        if item.event_kind is RuntimeEventKind.MMIO_WRITE
        and item.pc is not None
        and item.pc.value == "0x40200008"
        and item.physical_address is not None
        and item.physical_address.value == "0x9000000"
    )
    assert mmio.is_io is True
    evidence = RuntimeEvidenceNormalizer().normalize(mmio, result.runtime_trace)
    assert evidence.verified is True
    assert evidence.type.value == "dynamic_analysis"
