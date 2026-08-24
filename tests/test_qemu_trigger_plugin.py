"""Offline source and fixture audit for the dedicated Step 3A observer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.fixtures.phase9c.arm_a32_trigger_runtime.generate_fixture import build_elf


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "phase9c" / "arm_a32_trigger_runtime"
TRIGGER_PLUGIN = (
    ROOT / "tools" / "qemu_plugins" / "chipchain_trigger_sequence_observer.c"
)
STABLE_PLUGIN = ROOT / "tools" / "qemu_plugins" / "chipchain_runtime_observer.c"


def test_runtime_fixture_is_reproducible_owned_and_has_two_static_targets() -> None:
    elf = (FIXTURE / "arm_a32_trigger_runtime.elf").read_bytes()
    truth = json.loads((FIXTURE / "ground_truth.json").read_text("utf-8"))
    digest = hashlib.sha256(elf).hexdigest()

    assert elf == build_elf()
    assert truth["artifact_sha256"] == digest
    assert (FIXTURE / "SHA256SUMS").read_text("ascii") == (
        f"{digest}  arm_a32_trigger_runtime.elf\n"
    )
    assert len(truth["static_occurrences"]) == 2
    assert truth["expected_runtime_static_function"] == "executed_trigger"
    assert truth["not_executed_static_function"] == "not_called_trigger"
    assert set(truth["classification"]) == {
        "owned",
        "synthetic",
        "fixture",
        "not_real_vulnerability",
        "not_benchmark",
    }


def test_trigger_observer_copies_metadata_then_emits_only_on_execution() -> None:
    source = TRIGGER_PLUGIN.read_text("utf-8")

    assert TRIGGER_PLUGIN != STABLE_PLUGIN
    assert "qemu_plugin_insn_vaddr(instruction)" in source
    assert "qemu_plugin_insn_size(instruction)" in source
    assert "qemu_plugin_insn_data(instruction, metadata->bytes, size)" in source
    assert "qemu_plugin_register_vcpu_insn_exec_cb" in source
    assert "QEMU_PLUGIN_CB_NO_REGS" in source
    assert "emit_instruction(unsigned int vcpu_index" in source
    assert "write_record_locked(record)" in source
    translate_body = source.split("static void translate_block", 1)[1].split(
        "static void observer_exit", 1
    )[0]
    assert "write_record_locked" not in translate_body
    assert "qemu_plugin_insn *" not in source.split(
        "typedef struct InstructionMetadata", 1
    )[1].split("} InstructionMetadata", 1)[0]


def test_trigger_observer_has_no_register_memory_or_guest_mutation_api() -> None:
    source = TRIGGER_PLUGIN.read_text("utf-8")
    forbidden = {
        "qemu_plugin_" + "read_register",
        "qemu_plugin_" + "write_register",
        "qemu_plugin_" + "get_registers",
        "qemu_plugin_" + "set_pc",
        "qemu_plugin_" + "write_memory_vaddr",
        "qemu_plugin_" + "write_memory_hwaddr",
        "qemu_plugin_" + "mem_get_value",
        "qemu_plugin_" + "register_vcpu_mem_cb",
    }
    assert all(name not in source for name in forbidden)
    assert 'strcmp(info->target_name, "arm")' in source
    assert "info->system.smp_vcpus != 1" in source
    assert "chipchain_qemu_trigger_sequence_trace" in source
    assert "chipchain_qemu_raw_trace" not in source


def test_phase9b1_observer_remains_separate_and_has_no_instruction_data_upgrade() -> None:
    stable = STABLE_PLUGIN.read_text("utf-8")
    assert "chipchain_qemu_raw_trace" in stable
    assert '"format_version\\\":2' in stable
    assert "qemu_plugin_insn_data" not in stable
    assert "chipchain_qemu_trigger_sequence_trace" not in stable
