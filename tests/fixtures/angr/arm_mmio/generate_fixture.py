"""Generate the owned synthetic ARM32 MMIO observation ELF.

Every encoded A32 word is mirrored in arm_mmio.S. The generated program
contains known-MMIO, ordinary-RAM, and unresolved memory accesses so positive
and negative classification share the same real machine-code artifact.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path


BASE_ADDRESS = 0x10000
TEXT_OFFSET = 0x100


@dataclass(frozen=True)
class Function:
    """One symbol-backed function and its auditable A32 machine words."""

    name: str
    words: tuple[int, ...]


FUNCTIONS = (
    Function(
        "driver_like_function",
        (
            0xE3001000,  # movw r1, #0x0000
            0xE3441000,  # movt r1, #0x4000
            0xE5810000,  # str r0, [r1]  (known MMIO)
            0xE5810000,  # str r0, [r1]  (same hardware resource)
            0xE5914000,  # ldr r4, [r1]  (known MMIO)
            0xE3012000,  # movw r2, #0x1000
            0xE3422000,  # movt r2, #0x2000
            0xE5820000,  # str r0, [r2]  (ordinary RAM)
            0xE5924000,  # ldr r4, [r2]  (ordinary RAM)
            0xE5830000,  # str r0, [r3]  (unresolved address)
            0xE5954000,  # ldr r4, [r5]  (unresolved address)
            0xE12FFF1E,  # bx lr
        ),
    ),
    Function(
        "main",
        (
            0xE3A00001,  # mov r0, #1
            0xEBFFFFF1,  # bl driver_like_function
            0xEAFFFFFE,  # b .
        ),
    ),
)


def align(value: int, alignment: int) -> int:
    """Return value rounded up to alignment."""

    return (value + alignment - 1) & ~(alignment - 1)


def build_elf() -> tuple[bytes, dict[str, object]]:
    """Build a deterministic ELF32 little-endian ARM executable and truth map."""

    text = bytearray()
    functions: list[dict[str, object]] = []
    cursor = BASE_ADDRESS
    for function in FUNCTIONS:
        encoded = b"".join(struct.pack("<I", word) for word in function.words)
        functions.append(
            {"name": function.name, "address": hex(cursor), "size": len(encoded)}
        )
        text.extend(encoded)
        cursor += len(encoded)

    entry_point = next(
        int(str(item["address"]), 16)
        for item in functions
        if item["name"] == "main"
    )
    string_table = bytearray(b"\x00")
    name_offsets: dict[str, int] = {}
    for function in FUNCTIONS:
        name_offsets[function.name] = len(string_table)
        string_table.extend(function.name.encode("ascii") + b"\x00")

    symbol_table = bytearray(16)
    for function, truth in zip(FUNCTIONS, functions, strict=True):
        symbol_table.extend(
            struct.pack(
                "<IIIBBH",
                name_offsets[function.name],
                int(str(truth["address"]), 16),
                int(truth["size"]),
                0x12,
                0,
                1,
            )
        )

    section_names = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
    section_name_offsets = {
        name: section_names.index(name.encode("ascii"))
        for name in (".text", ".symtab", ".strtab", ".shstrtab")
    }
    symbol_offset = align(TEXT_OFFSET + len(text), 4)
    string_offset = symbol_offset + len(symbol_table)
    section_name_offset = string_offset + len(string_table)
    section_header_offset = align(section_name_offset + len(section_names), 4)

    elf_header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x01\x01" + b"\x00" * 9,
        2, 40, 1, entry_point, 52, section_header_offset, 0x05000200,
        52, 32, 1, 40, 5, 4,
    )
    program_header = struct.pack(
        "<IIIIIIII",
        1, TEXT_OFFSET, BASE_ADDRESS, BASE_ADDRESS, len(text), len(text), 5, 0x100,
    )

    section_headers = bytearray(40)
    section_headers.extend(
        struct.pack(
            "<IIIIIIIIII",
            section_name_offsets[".text"], 1, 0x6, BASE_ADDRESS, TEXT_OFFSET,
            len(text), 0, 0, 4, 0,
        )
    )
    section_headers.extend(
        struct.pack(
            "<IIIIIIIIII",
            section_name_offsets[".symtab"], 2, 0, 0, symbol_offset,
            len(symbol_table), 3, 1, 4, 16,
        )
    )
    section_headers.extend(
        struct.pack(
            "<IIIIIIIIII",
            section_name_offsets[".strtab"], 3, 0, 0, string_offset,
            len(string_table), 0, 0, 1, 0,
        )
    )
    section_headers.extend(
        struct.pack(
            "<IIIIIIIIII",
            section_name_offsets[".shstrtab"], 3, 0, 0, section_name_offset,
            len(section_names), 0, 0, 1, 0,
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

    ground_truth: dict[str, object] = {
        "fixture_type": "synthetic",
        "owned": True,
        "vulnerability_sample": False,
        "architecture": "ARM",
        "format": "ELF32 little-endian ARM A32",
        "entry_point": hex(entry_point),
        "functions": functions,
        "calls": [
            {
                "caller": "main",
                "callee": "driver_like_function",
                "callsite": "0x10034",
                "instruction": "bl driver_like_function",
            }
        ],
        "expected_mmio_accesses": [
            {
                "function": "driver_like_function",
                "instruction_address": "0x10008",
                "instruction": "str r0, [r1]",
                "access_type": "mmio_write",
                "target": "0x40000000",
                "region": "fixture-mmio-register",
            },
            {
                "function": "driver_like_function",
                "instruction_address": "0x1000c",
                "instruction": "str r0, [r1]",
                "access_type": "mmio_write",
                "target": "0x40000000",
                "region": "fixture-mmio-register",
            },
            {
                "function": "driver_like_function",
                "instruction_address": "0x10010",
                "instruction": "ldr r4, [r1]",
                "access_type": "mmio_read",
                "target": "0x40000000",
                "region": "fixture-mmio-register",
            },
        ],
        "non_mmio_accesses": [
            {
                "instruction_address": "0x1001c",
                "instruction": "str r0, [r2]",
                "target": "0x20001000",
            },
            {
                "instruction_address": "0x10020",
                "instruction": "ldr r4, [r2]",
                "target": "0x20001000",
            },
        ],
        "unresolved_memory_accesses": [
            {"instruction_address": "0x10024", "instruction": "str r0, [r3]"},
            {"instruction_address": "0x10028", "instruction": "ldr r4, [r5]"},
        ],
    }
    return bytes(image), ground_truth


def main() -> None:
    """Write the fixture, digest, and machine-readable Ground Truth."""

    fixture_dir = Path(__file__).resolve().parent
    binary, ground_truth = build_elf()
    binary_path = fixture_dir / "arm_mmio.elf"
    binary_path.write_bytes(binary)
    digest = hashlib.sha256(binary).hexdigest()
    (fixture_dir / "SHA256SUMS").write_text(
        f"{digest}  {binary_path.name}\n", encoding="ascii"
    )
    (fixture_dir / "ground_truth.json").write_text(
        json.dumps(ground_truth, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {binary_path} ({len(binary)} bytes, sha256={digest})")


if __name__ == "__main__":
    main()
