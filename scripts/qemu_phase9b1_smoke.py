"""Run the explicit real-QEMU Phase 9B1 owned-fixture smoke test."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

from chipchain.runtime import RuntimeEvidenceNormalizer, RuntimeEventKind
from chipchain.runtime.qemu import QemuArmPassiveRunConfig, QemuPassiveRuntimeRunner


ROOT = Path(__file__).resolve().parents[1]
FIRMWARE = ROOT / "tests" / "fixtures" / "qemu_arm_baremetal" / "arm_qemu_mmio.elf"
EXPECTED_MMIO_PC = "0x40200008"
EXPECTED_MMIO_PADDR = "0x9000000"


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
            run_id="owned-qemu-mmio-run",
            scenario_id="owned-qemu-mmio-scenario",
            artifact_id="owned-qemu-mmio-raw-v1",
            firmware_sha256=firmware_sha,
            timeout_seconds=30,
        )
        result = QemuPassiveRuntimeRunner().run(config)
        counts = Counter(item.event_kind for item in result.runtime_trace.observations)
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
        if instruction_count <= 0 or expected_mmio is None:
            print("REAL_QEMU_STATUS = FAILED_EXPECTED_OBSERVATION_MISSING")
            return 1
        evidence = RuntimeEvidenceNormalizer().normalize(
            expected_mmio, result.runtime_trace
        )
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
        print(f"mmio_write_count = {counts[RuntimeEventKind.MMIO_WRITE]}")
        print(f"mmio_pc = {expected_mmio.pc.value}")
        print(f"mmio_paddr = {expected_mmio.physical_address.value}")
        print(f"evidence_id = {evidence.id}")
        print(f"evidence_type = {evidence.type.value}")
        print(f"evidence_verified = {str(evidence.verified).lower()}")
        print("meaning_boundary = runtime observation only; no interaction or vulnerability verdict")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
