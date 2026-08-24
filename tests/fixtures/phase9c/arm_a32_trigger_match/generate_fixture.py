"""Generate the owned synthetic ELF for Phase 9C Step 2.

The generator writes only the explicitly listed harmless A32 words.  It is a
toolchain-independent reproducibility aid, not a firmware matcher or result.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path


TEXT_ADDRESS = 0x00010000
DATA_ADDRESS = 0x00020000
TEXT_OFFSET = 0x100
DATA_OFFSET = 0x200
SIGNATURE_ID = (
    "hardware-trigger-signature:"
    "ad8e4d41c15292796475122a07dc276aaee34b27433b6be3c6c4243a9d676d99"
)


@dataclass(frozen=True)
class Function:
    """One symbol-backed synthetic function and exact A32 words."""

    name: str
    words: tuple[int, ...]


TRIGGER_WORDS = (0xE3A00001, 0xE2801001, 0xE1A02001)
FUNCTIONS = (
    Function(
        "synthetic_trigger_function",
        (*TRIGGER_WORDS, 0xE12FFF1E),  # bx lr
    ),
    Function(
        "synthetic_near_miss",
        (0xE3A00001, 0xE2801002, 0xE1A02001, 0xE12FFF1E),
    ),
)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build_elf() -> tuple[bytes, dict[str, object]]:
    """Return deterministic ELF32 bytes and layout-derived Ground Truth."""

    text = bytearray()
    functions: list[dict[str, object]] = []
    cursor = TEXT_ADDRESS
    for function in FUNCTIONS:
        encoded = b"".join(struct.pack("<I", word) for word in function.words)
        functions.append(
            {
                "name": function.name,
                "address": f"0x{cursor:08x}",
                "size": len(encoded),
                "words": [f"0x{word:08x}" for word in function.words],
            }
        )
        text.extend(encoded)
        cursor += len(encoded)
    data = b"".join(struct.pack("<I", word) for word in TRIGGER_WORDS)

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
                0x12,  # STB_GLOBAL | STT_FUNC
                0,
                1,  # .text
            )
        )

    section_names = b"\x00.text\x00.data\x00.symtab\x00.strtab\x00.shstrtab\x00"
    section_name_offsets = {
        name: section_names.index(name.encode("ascii"))
        for name in (".text", ".data", ".symtab", ".strtab", ".shstrtab")
    }
    symbol_offset = _align(DATA_OFFSET + len(data), 4)
    string_offset = symbol_offset + len(symbol_table)
    section_name_offset = string_offset + len(string_table)
    section_header_offset = _align(section_name_offset + len(section_names), 4)

    elf_header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x01\x01" + b"\x00" * 9,
        2,  # ET_EXEC
        40,  # EM_ARM
        1,
        TEXT_ADDRESS,
        52,
        section_header_offset,
        0x05000200,
        52,
        32,
        2,
        40,
        6,
        5,
    )
    program_headers = b"".join(
        (
            struct.pack(
                "<IIIIIIII",
                1,
                TEXT_OFFSET,
                TEXT_ADDRESS,
                TEXT_ADDRESS,
                len(text),
                len(text),
                5,  # PF_R | PF_X
                0x100,
            ),
            struct.pack(
                "<IIIIIIII",
                1,
                DATA_OFFSET,
                DATA_ADDRESS,
                DATA_ADDRESS,
                len(data),
                len(data),
                6,  # PF_R | PF_W, deliberately non-executable
                0x100,
            ),
        )
    )

    section_headers = bytearray(40)
    section_headers.extend(
        struct.pack(
            "<IIIIIIIIII",
            section_name_offsets[".text"],
            1,
            0x6,  # SHF_ALLOC | SHF_EXECINSTR
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
            "<IIIIIIIIII",
            section_name_offsets[".data"],
            1,
            0x3,  # SHF_ALLOC | SHF_WRITE, no SHF_EXECINSTR
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
            "<IIIIIIIIII",
            section_name_offsets[".symtab"],
            2,
            0,
            0,
            symbol_offset,
            len(symbol_table),
            4,
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

    trigger_function = functions[0]
    trigger_address = int(str(trigger_function["address"]), 16)
    ground_truth: dict[str, object] = {
        "fixture_type": "owned_synthetic",
        "real_hardware_vulnerability": False,
        "architecture": "ARM",
        "execution_mode": "arm_a32",
        "format": "ELF32 little-endian ARM A32",
        "entry_point": f"0x{TEXT_ADDRESS:08x}",
        "signature_id": SIGNATURE_ID,
        "expected_match": {
            "function": trigger_function["name"],
            "function_address": trigger_function["address"],
            "instruction_addresses": [
                f"0x{trigger_address + index * 4:08x}"
                for index in range(len(TRIGGER_WORDS))
            ],
            "instruction_words": [
                f"0x{word:08x}" for word in TRIGGER_WORDS
            ],
            "basic_block_path": [trigger_function["address"]],
        },
        "near_miss": functions[1],
        "non_executable_copy": {
            "section": ".data",
            "address": f"0x{DATA_ADDRESS:08x}",
            "file_offset": f"0x{DATA_OFFSET:08x}",
            "instruction_words": [
                f"0x{word:08x}" for word in TRIGGER_WORDS
            ],
        },
    }
    return bytes(image), ground_truth


def main() -> None:
    """Write the ELF, content hash, and layout-derived Ground Truth."""

    fixture_directory = Path(__file__).resolve().parent
    binary, ground_truth = build_elf()
    binary_path = fixture_directory / "arm_a32_trigger_match.elf"
    binary_path.write_bytes(binary)
    digest = hashlib.sha256(binary).hexdigest()
    ground_truth["artifact_sha256"] = digest
    (fixture_directory / "SHA256SUMS").write_text(
        f"{digest}  {binary_path.name}\n",
        encoding="ascii",
    )
    (fixture_directory / "ground_truth.json").write_text(
        json.dumps(ground_truth, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {binary_path.name} ({len(binary)} bytes, sha256={digest})")


if __name__ == "__main__":
    main()
