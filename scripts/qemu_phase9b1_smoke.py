"""Run the explicit real-QEMU Phase 9B1 owned-fixture smoke test."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

from chipchain.runtime import RuntimeEvidenceNormalizer, RuntimeEventKind
from chipchain.runtime.qemu import (
    QemuArmPassiveRunConfig,
    QemuPassiveRuntimeRunner,
    QemuRawEventKind,
)


ROOT = Path(__file__).resolve().parents[1]
FIRMWARE = ROOT / "tests" / "fixtures" / "qemu_arm_baremetal" / "arm_qemu_mmio.elf"
EXPECTED_MMIO_PC = "0x40200008"
EXPECTED_MMIO_PADDR = "0x9000000"
EXPECTED_INSTRUCTION_PCS = {
    "0x40200000",
    "0x40200004",
    "0x40200008",
    "0x4020000c",
    "0x40200010",
    "0x40200014",
}
_PL011_ORACLE = re.compile(
    r"pl011_write.*addr 0x0+.*value 0x0*41.*reg DR"
)


def _default_plugin() -> Path:
    suffix = ".dll" if os.name == "nt" else ".dylib" if sys.platform == "darwin" else ".so"
    return ROOT / "tools" / "qemu_plugins" / f"chipchain_runtime_observer{suffix}"


def _resolve_inputs() -> tuple[Path | None, Path]:
    configured_qemu = os.environ.get("CHIPCHAIN_QEMU_SYSTEM_ARM")
    qemu = configured_qemu or shutil.which("qemu-system-arm")
    plugin = Path(os.environ.get("CHIPCHAIN_QEMU_PLUGIN", _default_plugin()))
    return Path(qemu) if qemu else None, plugin


def main() -> int:
    qemu, plugin = _resolve_inputs()
    missing: list[str] = []
    if qemu is None or not qemu.is_file():
        missing.append("qemu-system-arm")
    if not plugin.is_file():
        missing.append("compiled passive QEMU plugin")
    if not FIRMWARE.is_file():
        missing.append("owned ARM fixture ELF")
    if missing:
        print("REAL_QEMU_STATUS = BLOCKED")
        print(f"missing_components = {', '.join(missing)}")
        print("detection_commands = qemu-system-arm --version; python tools/qemu_plugins/build.py")
        return 2

    firmware_sha = hashlib.sha256(FIRMWARE.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="chipchain-qemu-") as directory:
        config = QemuArmPassiveRunConfig(
            qemu_executable=qemu,
            plugin_path=plugin,
            firmware_elf=FIRMWARE,
            raw_trace_path=Path(directory) / "phase9b1-raw.jsonl",
            topology_artifact_path=Path(directory) / "phase9b1-mtree-flat.txt",
            reference_pl011_trace_path=Path(directory) / "phase9b1-pl011.trace",
            run_id="owned-qemu-mmio-run",
            scenario_id="owned-qemu-mmio-scenario",
            artifact_id="owned-qemu-mmio-raw-v2",
            firmware_sha256=firmware_sha,
            timeout_seconds=30,
        )
        result = QemuPassiveRuntimeRunner().run(config)
        raw_counts = Counter(item.event_kind for item in result.parsed_trace.events)
        counts = Counter(item.event_kind for item in result.runtime_trace.observations)
        raw_target = next(
            (
                item
                for item in result.parsed_trace.events
                if item.event_kind is QemuRawEventKind.MEMORY_WRITE
                and item.pc.value == EXPECTED_MMIO_PC
                and item.physical_address is not None
                and item.physical_address.value == EXPECTED_MMIO_PADDR
                and item.access_size == 1
            ),
            None,
        )
        expected_mmio = next(
            (
                item
                for item in result.runtime_trace.observations
                if item.event_kind is RuntimeEventKind.MMIO_WRITE
                and item.pc is not None
                and item.pc.value == EXPECTED_MMIO_PC
                and item.physical_address is not None
                and item.physical_address.value == EXPECTED_MMIO_PADDR
            ),
            None,
        )
        instruction_count = counts[RuntimeEventKind.INSTRUCTION_EXEC]
        instruction_pcs = {
            item.pc.value
            for item in result.runtime_trace.observations
            if item.event_kind is RuntimeEventKind.INSTRUCTION_EXEC
            and item.pc is not None
        }
        target_region = next(
            (
                item
                for item in result.topology.regions
                if item.start <= 0x09000000 <= item.end
            ),
            None,
        )
        oracle = config.reference_pl011_trace_path.read_text(
            "utf-8", errors="replace"
        )
        oracle_pass = _PL011_ORACLE.search(oracle) is not None
        if (
            not EXPECTED_INSTRUCTION_PCS <= instruction_pcs
            or raw_target is None
            or raw_target.plugin_is_io is not False
            or raw_target.plugin_device_name != "RAM"
            or target_region is None
            or target_region.kind.value != "i/o"
            or target_region.name != "pl011"
            or expected_mmio is None
            or not result.parsed_trace.end.clean_shutdown
            or not oracle_pass
        ):
            print("REAL_QEMU_STATUS = FAILED_EXPECTED_OBSERVATION_MISSING")
            return 1
        evidence = RuntimeEvidenceNormalizer().normalize(
            expected_mmio, result.runtime_trace
        )
        if (
            expected_mmio.metadata.get("classification_source")
            != "qemu_machine_topology"
            or expected_mmio.metadata.get(
                "topology_plugin_classification_disagreed"
            )
            is not True
            or result.runtime_trace.manifest.memory_map_id != result.topology.id
            or result.runtime_trace.manifest.memory_map_sha256
            != result.topology.artifact_sha256
            or not evidence.verified
        ):
            print("REAL_QEMU_STATUS = FAILED_PROVENANCE_OR_EVIDENCE")
            return 1
        print("REAL_QEMU_STATUS = PASS")
        print(f"qemu_version = {result.environment.qemu_version}")
        print(
            "plugin_api = "
            f"{result.environment.plugin_api_min}..{result.environment.plugin_api_current}"
        )
        print(
            "instruction_event_count = "
            f"{instruction_count}"
        )
        print(
            "raw_memory_read_count = "
            f"{raw_counts[QemuRawEventKind.MEMORY_READ]}"
        )
        print(
            "raw_memory_write_count = "
            f"{raw_counts[QemuRawEventKind.MEMORY_WRITE]}"
        )
        print(f"plugin_is_io_for_target = {str(raw_target.plugin_is_io).lower()}")
        print(f"plugin_device_name_for_target = {raw_target.plugin_device_name}")
        print(f"topology_memory_map_id = {result.topology.id}")
        print(
            "topology_memory_map_sha256 = "
            f"{result.topology.artifact_sha256}"
        )
        print(f"topology_target_region_kind = {target_region.kind.value}")
        print(f"topology_target_region_name = {target_region.name}")
        print(f"mmio_write_count = {counts[RuntimeEventKind.MMIO_WRITE]}")
        print(f"mmio_pc = {expected_mmio.pc.value}")
        print(f"mmio_paddr = {expected_mmio.physical_address.value}")
        print(f"mmio_access_size = {expected_mmio.access_size}")
        print(
            "classification_source = "
            f"{expected_mmio.metadata['classification_source']}"
        )
        print(
            "classification_disagreement = "
            f"{str(expected_mmio.metadata['topology_plugin_classification_disagreed']).lower()}"
        )
        print(f"evidence_id = {evidence.id}")
        print(f"evidence_type = {evidence.type.value}")
        print(f"evidence_verified = {str(evidence.verified).lower()}")
        print("pl011_oracle = passed")
        print("meaning_boundary = runtime observation only; no interaction or vulnerability verdict")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
