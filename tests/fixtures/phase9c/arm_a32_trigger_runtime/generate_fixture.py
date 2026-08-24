"""Generate the deterministic owned Phase 9C Step 3A ARM A32 ELF."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path


BASE_ADDRESS = 0x40200000
TEXT_OFFSET = 0x1000
ARTIFACT_ID = "synthetic-owned-arm-a32-trigger-runtime-elf"
HARDWARE_VULNERABILITY_ID = "synthetic-phase9c-runtime-trigger-contract"
TRIGGER_WORDS = (0xE3A00001, 0xE2801001, 0xE1A02001)
FUNCTIONS = (
    ("_start", BASE_ADDRESS, 0x18),
    ("executed_trigger", BASE_ADDRESS + 0x18, 0x10),
    ("not_called_trigger", BASE_ADDRESS + 0x28, 0x10),
)
TEXT_WORDS = (
    0xEB000004,  # bl executed_trigger
    0xE3A00018,  # mov r0, #SYS_EXIT
    0xE59F1000,  # ldr r1, [pc, #0]
    0xEF123456,  # A32 semihosting SVC
    0x00020026,  # ADP_Stopped_ApplicationExit
    0xEAFFFFFE,  # fallback loop
    *TRIGGER_WORDS,
    0xE12FFF1E,  # bx lr
    *TRIGGER_WORDS,
    0xE12FFF1E,  # bx lr
)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _canonical_sha256_id(prefix: str, payload: object) -> str:
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(canonical).hexdigest()}"


def _static_match(
    *, artifact_sha256: str, signature_id: str, name: str, address: int
) -> dict[str, object]:
    locations = [
        {
            "instruction_address": f"0x{address + offset:08x}",
            "instruction_word": f"0x{word:08x}",
            "basic_block_address": f"0x{address:08x}",
        }
        for offset, word in zip((0, 4, 8), TRIGGER_WORDS, strict=True)
    ]
    identity = _canonical_sha256_id(
        "static-firmware-trigger-match",
        {
            "architecture": "arm",
            "artifact_sha256": artifact_sha256,
            "basic_block_path": [f"0x{address:08x}"],
            "execution_mode": "arm_a32",
            "function_address": f"0x{address:08x}",
            "hardware_vulnerability_id": HARDWARE_VULNERABILITY_ID,
            "instruction_locations": locations,
            "signature_id": signature_id,
        },
    )
    return {
        "id": identity,
        "function": name,
        "function_address": f"0x{address:08x}",
        "instruction_addresses": [
            item["instruction_address"] for item in locations
        ],
        "instruction_words": [item["instruction_word"] for item in locations],
    }


def signature_document() -> dict[str, object]:
    """Return an empty-P, clearly synthetic hardware-side prior contract."""

    words = [f"0x{word:08x}" for word in TRIGGER_WORDS]
    preconditions = {
        "privilege_mode": None,
        "register_preconditions": [],
        "memory_preconditions": [],
    }
    effect = {
        "kind": "assertion_violation",
        "register": None,
        "expected_value": None,
        "observed_value": None,
        "assertion_id": "synthetic-runtime-trigger-assertion",
        "assertion_description": "Synthetic expected failure for contract testing only",
    }
    signature_payload = {
        "architecture": "arm",
        "execution_mode": "arm_a32",
        "expected_effect": effect,
        "hardware_vulnerability_id": HARDWARE_VULNERABILITY_ID,
        "instruction_sequence": words,
        "preconditions": preconditions,
    }
    identity = _canonical_sha256_id(
        "hardware-trigger-signature", signature_payload
    )
    return {
        "id": identity,
        "architecture": "arm",
        "execution_mode": "arm_a32",
        "hardware_vulnerability_id": HARDWARE_VULNERABILITY_ID,
        "instruction_sequence": words,
        "preconditions": preconditions,
        "expected_effect": effect,
        "proof": {
            "kind": "assertion_violation",
            "description": "Owned synthetic prior proof for Step 3A fixture",
            "reference_ids": ["fixture:phase9c:runtime-trigger:synthetic-proof"],
        },
        "metadata": {
            "fixture": True,
            "not_benchmark": True,
            "not_real_vulnerability": True,
            "owned": True,
            "synthetic": True,
        },
    }


def build_elf() -> bytes:
    """Build ELF32 with one executable segment and auditable function symbols."""

    text = struct.pack(f"<{len(TEXT_WORDS)}I", *TEXT_WORDS)
    string_table = bytearray(b"\x00")
    name_offsets: dict[str, int] = {}
    for name, _, _ in FUNCTIONS:
        name_offsets[name] = len(string_table)
        string_table.extend(name.encode("ascii") + b"\x00")
    symbol_table = bytearray(16)
    for name, address, size in FUNCTIONS:
        symbol_table.extend(
            struct.pack(
                "<IIIBBH", name_offsets[name], address, size, 0x12, 0, 1
            )
        )
    section_names = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
    section_name_offsets = {
        name: section_names.index(name.encode("ascii"))
        for name in (".text", ".symtab", ".strtab", ".shstrtab")
    }
    symbol_offset = _align(TEXT_OFFSET + len(text), 4)
    string_offset = symbol_offset + len(symbol_table)
    section_name_offset = string_offset + len(string_table)
    section_header_offset = _align(section_name_offset + len(section_names), 4)
    elf_header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x01\x01" + b"\x00" * 9,
        2,
        40,
        1,
        BASE_ADDRESS,
        52,
        section_header_offset,
        0x05000200,
        52,
        32,
        1,
        40,
        5,
        4,
    )
    program_header = struct.pack(
        "<IIIIIIII",
        1,
        TEXT_OFFSET,
        BASE_ADDRESS,
        BASE_ADDRESS,
        len(text),
        len(text),
        5,
        0x1000,
    )
    section_headers = bytearray(40)
    section_headers.extend(
        struct.pack(
            "<IIIIIIIIII",
            section_name_offsets[".text"],
            1,
            0x6,
            BASE_ADDRESS,
            TEXT_OFFSET,
            len(text),
            0,
            0,
            4,
            0,
        )
    )
    section_headers.extend(
        struct.pack(
            "<IIIIIIIIII",
            section_name_offsets[".symtab"],
            2,
            0,
            0,
            symbol_offset,
            len(symbol_table),
            3,
            1,
            4,
            16,
        )
    )
    section_headers.extend(
        struct.pack(
            "<IIIIIIIIII",
            section_name_offsets[".strtab"],
            3,
            0,
            0,
            string_offset,
            len(string_table),
            0,
            0,
            1,
            0,
        )
    )
    section_headers.extend(
        struct.pack(
            "<IIIIIIIIII",
            section_name_offsets[".shstrtab"],
            3,
            0,
            0,
            section_name_offset,
            len(section_names),
            0,
            0,
            1,
            0,
        )
    )
    image = bytearray(elf_header + program_header)
    image.extend(b"\x00" * (TEXT_OFFSET - len(image)))
    image.extend(text)
    image.extend(b"\x00" * (symbol_offset - len(image)))
    image.extend(symbol_table)
    image.extend(string_table)
    image.extend(section_names)
    image.extend(b"\x00" * (section_header_offset - len(image)))
    image.extend(section_headers)
    return bytes(image)


def main() -> None:
    root = Path(__file__).resolve().parent
    elf = build_elf()
    digest = hashlib.sha256(elf).hexdigest()
    signature = signature_document()
    (root / "arm_a32_trigger_runtime.elf").write_bytes(elf)
    (root / "hardware_trigger_signature.json").write_text(
        json.dumps(signature, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (root / "ground_truth.json").write_text(
        json.dumps(
            {
                "architecture": "arm",
                "artifact_id": ARTIFACT_ID,
                "artifact_sha256": digest,
                "classification": [
                    "owned",
                    "synthetic",
                    "fixture",
                    "not_real_vulnerability",
                    "not_benchmark",
                ],
                "cpu": "cortex-a15",
                "entry_point": f"0x{BASE_ADDRESS:08x}",
                "execution_mode": "arm_a32",
                "expected_runtime_static_function": "executed_trigger",
                "not_executed_static_function": "not_called_trigger",
                "signature_id": signature["id"],
                "static_occurrences": [
                    _static_match(
                        artifact_sha256=digest,
                        signature_id=str(signature["id"]),
                        name=name,
                        address=address,
                    )
                    for name, address, _ in FUNCTIONS[1:]
                ],
                "machine": "virt",
                "reference_qemu_version": "11.0.3",
                "vcpu_count": 1,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "SHA256SUMS").write_text(
        f"{digest}  arm_a32_trigger_runtime.elf\n", encoding="ascii"
    )


if __name__ == "__main__":
    main()
