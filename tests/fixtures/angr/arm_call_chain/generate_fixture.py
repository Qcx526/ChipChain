"""Generate the auditable synthetic ARM32 ELF used by Phase 4 tests.

The fixture contains only the A32 instructions listed in ``FUNCTIONS``.  It is
generated directly because no ARM compiler is available in the validated
Windows environment.  This file is build input, not an analysis result.
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
            0xE2800003,  # add r0, r0, #3
            0xE12FFF1E,  # bx lr
        ),
    ),
    Function(
        "helper_function",
        (
            0xE92D4000,  # push {lr}
            0xE2800002,  # add r0, r0, #2
            0xEBFFFFFA,  # bl driver_like_function
            0xE8BD8000,  # pop {pc}
        ),
    ),
    Function(
        "parse_command",
        (
            0xE92D4000,  # push {lr}
            0xE2800001,  # add r0, r0, #1
            0xEBFFFFF8,  # bl helper_function
            0xE8BD8000,  # pop {pc}
        ),
    ),
    Function(
        "main",
        (
            0xE92D4000,  # push {lr}
            0xE3A00007,  # mov r0, #7
            0xEBFFFFF8,  # bl parse_command
            0xE8BD8000,  # pop {pc}
        ),
    ),
    Function(
        "indirect_dispatch",
        (
            0xE92D4000,  # push {lr}
            0xE12FFF33,  # blx r3 (intentionally unresolved target)
            0xE8BD8000,  # pop {pc}
        ),
    ),
)


def align(value: int, alignment: int) -> int:
    """Return *value* rounded up to *alignment*."""

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

    symbol_table = bytearray(16)  # ELF requires a null symbol at index zero.
    for function, truth in zip(FUNCTIONS, functions, strict=True):
        symbol_table.extend(
            struct.pack(
                "<IIIBBH",
                name_offsets[function.name],
                int(str(truth["address"]), 16),
                int(truth["size"]),
                0x12,  # STB_GLOBAL | STT_FUNC
                0,
                1,  # .text section index
            )
        )

    section_names = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
    section_name_offsets = {
        ".text": section_names.index(b".text"),
        ".symtab": section_names.index(b".symtab"),
        ".strtab": section_names.index(b".strtab"),
        ".shstrtab": section_names.index(b".shstrtab"),
    }

    symbol_offset = align(TEXT_OFFSET + len(text), 4)
    string_offset = symbol_offset + len(symbol_table)
    section_name_offset = string_offset + len(string_table)
    section_header_offset = align(section_name_offset + len(section_names), 4)

    elf_header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x01\x01" + b"\x00" * 9,
        2,  # ET_EXEC
        40,  # EM_ARM
        1,
        entry_point,
        52,
        section_header_offset,
        0x05000200,  # EABI5, soft-float ABI
        52,
        32,
        1,
        40,
        5,
        4,
    )
    program_header = struct.pack(
        "<IIIIIIII",
        1,  # PT_LOAD
        TEXT_OFFSET,
        BASE_ADDRESS,
        BASE_ADDRESS,
        len(text),
        len(text),
        5,  # PF_R | PF_X
        0x100,
    )

    section_headers = bytearray(40)  # Null section.
    section_headers.extend(
        struct.pack(
            "<IIIIIIIIII",
            section_name_offsets[".text"],
            1,  # SHT_PROGBITS
            0x6,  # SHF_ALLOC | SHF_EXECINSTR
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
            2,  # SHT_SYMTAB
            0,
            0,
            symbol_offset,
            len(symbol_table),
            3,  # Link to .strtab.
            1,  # One local symbol (the null entry).
            4,
            16,
        )
    )
    section_headers.extend(
        struct.pack(
            "<IIIIIIIIII",
            section_name_offsets[".strtab"],
            3,  # SHT_STRTAB
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
            3,  # SHT_STRTAB
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

    ground_truth: dict[str, object] = {
        "fixture_type": "synthetic",
        "architecture": "ARM",
        "format": "ELF32 little-endian ARM A32",
        "entry_point": hex(entry_point),
        "functions": functions,
        "calls": [
            {
                "caller": "helper_function",
                "callee": "driver_like_function",
                "callsite": "0x10010",
                "instruction": "bl driver_like_function",
            },
            {
                "caller": "parse_command",
                "callee": "helper_function",
                "callsite": "0x10020",
                "instruction": "bl helper_function",
            },
            {
                "caller": "main",
                "callee": "parse_command",
                "callsite": "0x10030",
                "instruction": "bl parse_command",
            },
        ],
        "unresolved_calls": [
            {
                "caller": "indirect_dispatch",
                "callsite": "0x1003c",
                "instruction": "blx r3",
                "reason": "register target is intentionally unconstrained",
            }
        ],
    }
    return bytes(image), ground_truth


def main() -> None:
    """Write the fixture, its SHA-256 digest, and machine-readable truth."""

    fixture_dir = Path(__file__).resolve().parent
    binary, ground_truth = build_elf()
    binary_path = fixture_dir / "arm_call_chain.elf"
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
