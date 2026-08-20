"""Opt-in real QEMU integration for the owned Phase 9B1 fixture."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from chipchain.runtime import RuntimeEvidenceNormalizer, RuntimeEventKind
from chipchain.runtime.qemu import (
    QemuArmPassiveRunConfig,
    QemuPassiveRuntimeRunner,
    QemuRawEventKind,
)


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
            topology_artifact_path=Path(directory) / "mtree-flat.txt",
            reference_pl011_trace_path=Path(directory) / "pl011.trace",
            run_id="owned-qemu-mmio-run",
            scenario_id="owned-qemu-mmio-scenario",
            artifact_id="owned-qemu-mmio-raw-v2",
            firmware_sha256=hashlib.sha256(firmware.read_bytes()).hexdigest(),
        )
        result = QemuPassiveRuntimeRunner().run(config)
        oracle = config.reference_pl011_trace_path.read_text("utf-8", errors="replace")
        assert re.search(
            r"pl011_write.*addr 0x0+.*value 0x0*41.*reg DR", oracle
        )
    assert result.environment.qemu_version == "11.0.3"
    assert result.environment.plugin_api_min == 2
    assert result.environment.plugin_api_current == 6
    assert result.parsed_trace.header.plugin_build_api_version == 6
    assert result.parsed_trace.end.clean_shutdown is True
    assert {
        item.pc.value
        for item in result.runtime_trace.observations
        if item.event_kind is RuntimeEventKind.INSTRUCTION_EXEC
        and item.pc is not None
    } >= {
        "0x40200000",
        "0x40200004",
        "0x40200008",
        "0x4020000c",
        "0x40200010",
        "0x40200014",
    }
    raw_target = next(
        item
        for item in result.parsed_trace.events
        if item.event_kind is QemuRawEventKind.MEMORY_WRITE
        and item.pc.value == "0x40200008"
        and item.physical_address is not None
        and item.physical_address.value == "0x9000000"
        and item.access_size == 1
    )
    assert raw_target.plugin_is_io is False
    assert raw_target.plugin_device_name == "RAM"
    region = next(
        item
        for item in result.topology.regions
        if item.start <= 0x09000000 <= item.end
    )
    assert region.kind.value == "i/o"
    assert region.name == "pl011"
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
    assert mmio.access_size == 1
    assert mmio.metadata["classification_source"] == "qemu_machine_topology"
    assert mmio.metadata["plugin_is_io"] is False
    assert mmio.metadata["topology_region_name"] == "pl011"
    assert mmio.metadata["topology_plugin_classification_disagreed"] is True
    assert result.runtime_trace.manifest.memory_map_id == result.topology.id
    assert (
        result.runtime_trace.manifest.memory_map_sha256
        == result.topology.artifact_sha256
    )
    evidence = RuntimeEvidenceNormalizer().normalize(mmio, result.runtime_trace)
    assert evidence.verified is True
    assert evidence.type.value == "dynamic_analysis"
