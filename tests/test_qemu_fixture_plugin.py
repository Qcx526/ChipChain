"""Audit the owned ELF fixture and passive observer source offline."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.fixtures.qemu_arm_baremetal.generate_fixture import build_elf


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "qemu_arm_baremetal"
PLUGIN = ROOT / "tools" / "qemu_plugins" / "chipchain_runtime_observer.c"


def test_owned_qemu_fixture_is_deterministic_and_matches_provenance() -> None:
    elf = (FIXTURE / "arm_qemu_mmio.elf").read_bytes()
    digest = hashlib.sha256(elf).hexdigest()
    ground_truth = json.loads((FIXTURE / "ground_truth.json").read_text("utf-8"))

    assert elf == build_elf()
    assert digest == ground_truth["firmware_sha256"]
    assert (FIXTURE / "SHA256SUMS").read_text("ascii") == (
        f"{digest}  arm_qemu_mmio.elf\n"
    )
    assert set(ground_truth["classification"]) == {
        "owned",
        "synthetic",
        "fixture",
        "not_real_vulnerability",
        "not_benchmark",
    }
    assert ground_truth["expected_mmio"]["physical_address"] == 0x09000000


def test_fixture_is_arm32_little_endian_executable() -> None:
    elf = (FIXTURE / "arm_qemu_mmio.elf").read_bytes()

    assert elf[:7] == b"\x7fELF\x01\x01\x01"
    assert int.from_bytes(elf[18:20], "little") == 40
    assert int.from_bytes(elf[24:28], "little") == 0x40000000


def test_observer_uses_required_passive_qemu_apis_only() -> None:
    source = PLUGIN.read_text("utf-8")
    required = {
        "qemu_plugin_register_vcpu_tb_trans_cb",
        "qemu_plugin_tb_n_insns",
        "qemu_plugin_tb_get_insn",
        "qemu_plugin_insn_vaddr",
        "qemu_plugin_register_vcpu_insn_exec_cb",
        "qemu_plugin_register_vcpu_mem_cb",
        "qemu_plugin_get_hwaddr",
        "qemu_plugin_hwaddr_is_io",
        "qemu_plugin_hwaddr_phys_addr",
        "qemu_plugin_mem_is_store",
        "qemu_plugin_mem_size_shift",
    }
    forbidden = {
        "qemu_plugin_" + "write_register",
        "qemu_plugin_" + "set_pc",
        "qemu_plugin_" + "write_memory_vaddr",
        "qemu_plugin_" + "write_memory_hwaddr",
        "qemu_plugin_" + "mem_get_value",
        "qemu_plugin_" + "read_register",
    }

    assert required <= {name for name in required if name in source}
    assert all(name not in source for name in forbidden)
    assert "QEMU_PLUGIN_CB_NO_REGS" in source
    assert "qemu_plugin_hwaddr_is_io(hwaddr)" in source
    assert "translate_block(qemu_plugin_id_t id" in source
    assert "observer_exit(qemu_plugin_id_t id" in source
    assert all(
        field not in source
        for field in (
            "\"vulnerability_id\"",
            "\"interaction_id\"",
            "\"reference_role\"",
            "\"verification_status\"",
            "\"score\"",
            "\"root_cause\"",
        )
    )


def test_uart_fixture_address_does_not_leak_into_runtime_implementation() -> None:
    runtime_source = "\n".join(
        path.read_text("utf-8")
        for path in (ROOT / "src" / "chipchain" / "runtime").rglob("*.py")
    )
    assert "09000000" not in runtime_source
    assert "0x9000000" not in runtime_source
