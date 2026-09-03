"""Generate the deterministic owned AArch64 static-fusion fixture."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct


TEXT_ADDRESS = 0x400000
DATA_ADDRESS = 0x401000
TEXT_OFFSET = 0x1000
DATA_OFFSET = 0x2000
FUNCTION_NAME = "owned_fused_static_flow"

INSTRUCTIONS = (
    (0xD5387400, "mrs x0, par_el1", "system_register_read"),
    (0xB4000061, "cbz x1, block_c", None),
    (0xD5033B9F, "dsb ish", "memory_barrier"),
    (0x14000003, "b block_d", None),
    (0xD508831F, "tlbi vmalle1is", "tlb_invalidate"),
    (0x14000001, "b block_d", None),
    (0xD5033FDF, "isb", "instruction_barrier"),
    (0xD65F03C0, "ret", None),
)

INTENDED_BASIC_BLOCK_ADDRESSES = (
    "0x400000",
    "0x400008",
    "0x400010",
    "0x400018",
)
INTENDED_CFG_EDGES = (
    ("0x400000", "0x400008"),
    ("0x400000", "0x400010"),
    ("0x400008", "0x400018"),
    ("0x400010", "0x400018"),
)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build_elf() -> tuple[bytes, dict[str, object]]:
    """Return exact fixture bytes and independently auditable design intent."""

    text = b"".join(
        struct.pack("<I", word)
        for word, _assembly, _semantic in INSTRUCTIONS
    )
    data = b"".join(
        struct.pack("<I", value) for value in (0xD5387400, 0, 0xD5033FDF, 0)
    )
    string_table = b"\x00" + FUNCTION_NAME.encode("ascii") + b"\x00"
    symbol_table = bytearray(24)
    symbol_table.extend(
        struct.pack(
            "<IBBHQQ",
            1,
            0x12,
            0,
            1,
            TEXT_ADDRESS,
            len(text),
        )
    )
    section_names = b"\x00.text\x00.data\x00.symtab\x00.strtab\x00.shstrtab\x00"
    section_name_offsets = {
        name: section_names.index(name.encode("ascii"))
        for name in (".text", ".data", ".symtab", ".strtab", ".shstrtab")
    }
    symbol_offset = _align(DATA_OFFSET + len(data), 8)
    string_offset = symbol_offset + len(symbol_table)
    section_name_offset = string_offset + len(string_table)
    section_header_offset = _align(section_name_offset + len(section_names), 8)

    elf_header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        2,
        183,
        1,
        TEXT_ADDRESS,
        64,
        section_header_offset,
        0,
        64,
        56,
        2,
        64,
        6,
        5,
    )
    program_headers = b"".join(
        (
            struct.pack(
                "<IIQQQQQQ",
                1,
                5,
                TEXT_OFFSET,
                TEXT_ADDRESS,
                TEXT_ADDRESS,
                len(text),
                len(text),
                0x1000,
            ),
            struct.pack(
                "<IIQQQQQQ",
                1,
                6,
                DATA_OFFSET,
                DATA_ADDRESS,
                DATA_ADDRESS,
                len(data),
                len(data),
                0x1000,
            ),
        )
    )
    section_headers = bytearray(64)
    section_headers.extend(
        struct.pack(
            "<IIQQQQIIQQ",
            section_name_offsets[".text"],
            1,
            0x6,
            TEXT_ADDRESS,
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
            "<IIQQQQIIQQ",
            section_name_offsets[".data"],
            1,
            0x3,
            DATA_ADDRESS,
            DATA_OFFSET,
            len(data),
            0,
            0,
            4,
            0,
        )
    )
    section_headers.extend(
        struct.pack(
            "<IIQQQQIIQQ",
            section_name_offsets[".symtab"],
            2,
            0,
            0,
            symbol_offset,
            len(symbol_table),
            4,
            1,
            8,
            24,
        )
    )
    section_headers.extend(
        struct.pack(
            "<IIQQQQIIQQ",
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
            "<IIQQQQIIQQ",
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

    image = bytearray(elf_header + program_headers)
    image.extend(b"\x00" * (TEXT_OFFSET - len(image)))
    image.extend(text)
    image.extend(b"\x00" * (DATA_OFFSET - len(image)))
    image.extend(data)
    image.extend(b"\x00" * (symbol_offset - len(image)))
    image.extend(symbol_table)
    image.extend(string_table)
    image.extend(section_names)
    image.extend(b"\x00" * (section_header_offset - len(image)))
    image.extend(section_headers)

    design = {
        "fixture_classification": {
            "owned": True,
            "synthetic": True,
            "benign": True,
            "real_vulnerability": False,
            "runtime_execution_evidence": False,
            "triggerability_demonstration": False,
            "verified_attack_chain": False,
        },
        "architecture": "AARCH64",
        "format": "ELF64 little-endian AArch64",
        "function_name": FUNCTION_NAME,
        "function_address": hex(TEXT_ADDRESS),
        "instructions": [
            {
                "address": hex(TEXT_ADDRESS + index * 4),
                "word": f"0x{word:08x}",
                "assembly": assembly,
                "intended_recognized_semantic": semantic,
            }
            for index, (word, assembly, semantic) in enumerate(INSTRUCTIONS)
        ],
        "intended_basic_block_addresses": list(
            INTENDED_BASIC_BLOCK_ADDRESSES
        ),
        "intended_cfg_edges": [list(edge) for edge in INTENDED_CFG_EDGES],
    }
    return bytes(image), design


if __name__ == "__main__":
    directory = Path(__file__).resolve().parent
    image, design = build_elf()
    filename = "aarch64_static_fused_behavior_v1.elf"
    digest = hashlib.sha256(image).hexdigest()
    (directory / filename).write_bytes(image)
    (directory / "SHA256SUMS").write_text(
        f"{digest}  {filename}\n", encoding="ascii"
    )
    design["artifact_sha256"] = digest
    (directory / "expected_fixture_design.json").write_text(
        json.dumps(design, indent=2) + "\n", encoding="utf-8"
    )
