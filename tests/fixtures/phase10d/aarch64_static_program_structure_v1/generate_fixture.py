"""Generate the deterministic owned AArch64 static-structure fixture."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct


TEXT_ADDRESS = 0x400000
DATA_ADDRESS = 0x401000
TEXT_OFFSET = 0x1000
DATA_OFFSET = 0x2000

FUNCTIONS = (
    (
        "owned_branching_structure",
        (
            0xB4000060,  # cbz x0, owned_branch_target
            0x91000421,  # add x1, x1, #1
            0xD65F03C0,  # ret
            0xD1000421,  # sub x1, x1, #1
            0xD65F03C0,  # ret
        ),
    ),
    ("owned_leaf_structure", (0xD65F03C0,)),
    ("owned_self_loop_structure", (0x14000000,)),  # b .
)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build_elf() -> tuple[bytes, dict[str, object]]:
    """Return exact fixture bytes and design-derived structure expectations."""

    text = bytearray()
    layouts: list[dict[str, object]] = []
    for name, words in FUNCTIONS:
        address = TEXT_ADDRESS + len(text)
        encoded = b"".join(struct.pack("<I", word) for word in words)
        layouts.append(
            {
                "name": name,
                "address": address,
                "size": len(encoded),
            }
        )
        text.extend(encoded)

    data = b"".join(
        struct.pack("<I", word)
        for word in (0xB4000060, 0, 0x14000000, 0)
    )

    string_table = bytearray(b"\x00")
    name_offsets: dict[str, int] = {}
    for name, _words in FUNCTIONS:
        name_offsets[name] = len(string_table)
        string_table.extend(name.encode("ascii") + b"\x00")

    symbol_table = bytearray(24)
    for layout in layouts:
        name = str(layout["name"])
        symbol_table.extend(
            struct.pack(
                "<IBBHQQ",
                name_offsets[name],
                0x12,
                0,
                1,
                int(layout["address"]),
                int(layout["size"]),
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

    expected = {
        "fixture_classification": {
            "owned": True,
            "synthetic": True,
            "real_vulnerability": False,
            "runtime_execution_evidence": False,
        },
        "architecture": "AARCH64",
        "format": "ELF64 little-endian AArch64",
        "extractor_profile_id": (
            "phase10d_aarch64_static_program_structure_extractor_cfgfast_v1"
        ),
        "expected_inventory_id": (
            "static-program-structure-inventory:"
            "7c97b813bf68d6e7aac8d8512f27e48d097b36752db8209f5954bf20e118942c"
        ),
        "expected_functions": [
            {
                "function_name": "owned_branching_structure",
                "function_address": "0x400000",
                "basic_block_addresses": ["0x400000", "0x400004", "0x40000c"],
                "directed_edges": [
                    ["0x400000", "0x400004"],
                    ["0x400000", "0x40000c"],
                ],
            },
            {
                "function_name": "owned_leaf_structure",
                "function_address": "0x400014",
                "basic_block_addresses": ["0x400014"],
                "directed_edges": [],
            },
            {
                "function_name": "owned_self_loop_structure",
                "function_address": "0x400018",
                "basic_block_addresses": ["0x400018"],
                "directed_edges": [["0x400018", "0x400018"]],
            },
        ],
        "expected_diagnostic_codes": [
            "basic_block_count:5",
            "directed_cfg_edge_count:3",
            "function_cfg_count:3",
            "zero_edge_function_count:1",
        ],
        "non_executable_decoy": {
            "address": "0x401000",
            "section": ".data",
        },
    }
    return bytes(image), expected


if __name__ == "__main__":
    directory = Path(__file__).resolve().parent
    image, expected = build_elf()
    filename = "aarch64_static_program_structure_v1.elf"
    digest = hashlib.sha256(image).hexdigest()
    (directory / filename).write_bytes(image)
    (directory / "SHA256SUMS").write_text(
        f"{digest}  {filename}\n",
        encoding="ascii",
    )
    expected["artifact_sha256"] = digest
    (directory / "expected_static_structure.json").write_text(
        json.dumps(expected, indent=2) + "\n",
        encoding="utf-8",
    )
