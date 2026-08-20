"""Generate the deterministic owned ARM ELF from audited A32 machine words."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path


BASE_ADDRESS = 0x40000000
UART0_ADDRESS = 0x09000000
WORDS = (
    0xE59F0014,  # ldr r0, [pc, #20] -> UART literal
    0xE3A01041,  # mov r1, #'A'
    0xE5C01000,  # strb r1, [r0]
    0xE3A00018,  # mov r0, #SYS_EXIT
    0xE59F1000,  # ldr r1, [pc, #0] -> exit reason literal
    0xEF123456,  # Arm semihosting SVC
    0x00020026,  # ADP_Stopped_ApplicationExit
    UART0_ADDRESS,
)


def build_elf() -> bytes:
    ident = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8
    elf_header = ident + struct.pack(
        "<HHIIIIIHHHHHH",
        2,
        40,
        1,
        BASE_ADDRESS,
        52,
        0,
        0x05000000,
        52,
        32,
        1,
        40,
        0,
        0,
    )
    payload = struct.pack(f"<{len(WORDS)}I", *WORDS)
    program_header = struct.pack(
        "<IIIIIIII",
        1,
        0x1000,
        BASE_ADDRESS,
        BASE_ADDRESS,
        len(payload),
        len(payload),
        5,
        0x1000,
    )
    return elf_header + program_header + b"\x00" * (0x1000 - 84) + payload


def main() -> None:
    root = Path(__file__).resolve().parent
    elf = build_elf()
    elf_path = root / "arm_qemu_mmio.elf"
    elf_path.write_bytes(elf)
    digest = hashlib.sha256(elf).hexdigest()
    ground_truth = {
        "architecture": "arm",
        "classification": ["owned", "synthetic", "fixture", "not_real_vulnerability", "not_benchmark"],
        "entry_point": BASE_ADDRESS,
        "expected_mmio": {
            "access_size": 1,
            "event_kind": "mmio_write",
            "instruction_address": BASE_ADDRESS + 8,
            "physical_address": UART0_ADDRESS,
        },
        "firmware_sha256": digest,
        "machine": "virt",
        "cpu": "cortex-a15",
        "reference_qemu_version": "11.0.3",
        "vcpu_count": 1,
    }
    (root / "ground_truth.json").write_text(
        json.dumps(ground_truth, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (root / "SHA256SUMS").write_text(
        f"{digest}  arm_qemu_mmio.elf\n", encoding="ascii"
    )


if __name__ == "__main__":
    main()
