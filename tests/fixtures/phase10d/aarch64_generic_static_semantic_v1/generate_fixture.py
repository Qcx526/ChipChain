"""Generate the deterministic owned generic AArch64 semantic fixture."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct


TEXT_ADDRESS = 0x400000
DATA_ADDRESS = 0x401000
TEXT_OFFSET = 0x1000
DATA_OFFSET = 0x2000
FUNCTION_NAME = "owned_generic_semantic_inventory"
EXCEPTION_FUNCTION_NAME = "owned_exception_return_semantic"
RET = 0xD65F03C0
ERET = 0xD69F03E0

INSTRUCTIONS = (
    (0xF9400020, "memory_load", {"effective_memory_type_resolution": "requires_objective_translation_context"}),
    (0xF9000020, "memory_store", {"effective_memory_type_resolution": "requires_objective_translation_context"}),
    (
        0xC85F7C41,
        "load_exclusive",
        {
            "effective_memory_type_resolution": "requires_objective_translation_context",
            "memory_exclusivity": "exclusive_load",
        },
    ),
    (
        0xC8007C41,
        "store_exclusive",
        {
            "effective_memory_type_resolution": "requires_objective_translation_context",
            "memory_exclusivity": "exclusive_store",
        },
    ),
    (0xD5387400, "system_register_read", {"system_register": "par_el1"}),
    (0xD5187400, "system_register_write", {"system_register": "par_el1"}),
    (0xD5033B9F, "memory_barrier", {"barrier_kind": "dsb", "barrier_option": "ish"}),
    (0xD5033BBF, "memory_barrier", {"barrier_kind": "dmb", "barrier_option": "ish"}),
    (0xD5033FDF, "instruction_barrier", {"barrier_kind": "isb"}),
    (0xD508831F, "tlb_invalidate", {"tlb_operation": "vmalle1is"}),
    (0xD503201F, None, {}),
    (0x91000400, None, {}),
    (RET, None, {}),
)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build_elf() -> tuple[bytes, dict[str, object]]:
    """Return deterministic ELF64 bytes and decoder expectations."""

    generic_text = b"".join(
        struct.pack("<I", word) for word, _operation, _attributes in INSTRUCTIONS
    )
    exception_address = TEXT_ADDRESS + len(generic_text)
    text = generic_text + struct.pack("<I", ERET)
    semantic_words = [
        word for word, operation, _attributes in INSTRUCTIONS if operation is not None
    ]
    semantic_words.append(ERET)
    data_words = tuple(
        value for word in semantic_words for value in (word, 0)
    )
    data = b"".join(struct.pack("<I", word) for word in data_words)

    string_table = bytearray(b"\x00")
    name_offsets: dict[str, int] = {}
    for name in (FUNCTION_NAME, EXCEPTION_FUNCTION_NAME):
        name_offsets[name] = len(string_table)
        string_table.extend(name.encode("ascii") + b"\x00")
    symbol_table = bytearray(24)
    for name, address, size in (
        (FUNCTION_NAME, TEXT_ADDRESS, len(generic_text)),
        (EXCEPTION_FUNCTION_NAME, exception_address, 4),
    ):
        symbol_table.extend(
            struct.pack(
                "<IBBHQQ",
                name_offsets[name],
                0x12,
                0,
                1,
                address,
                size,
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

    expected_facts = []
    for index, (word, operation, attributes) in enumerate(INSTRUCTIONS):
        if operation is None:
            continue
        expected_facts.append(
            {
                "function": FUNCTION_NAME,
                "function_address": hex(TEXT_ADDRESS),
                "basic_block_address": hex(TEXT_ADDRESS),
                "instruction_address": hex(TEXT_ADDRESS + index * 4),
                "instruction_bytes": "0x" + struct.pack("<I", word).hex(),
                "instruction_size": 4,
                "operation": operation,
                "attributes": attributes,
            }
        )
    expected_facts.append(
        {
            "function": EXCEPTION_FUNCTION_NAME,
            "function_address": hex(exception_address),
            "basic_block_address": None,
            "instruction_address": hex(exception_address),
            "instruction_bytes": "0x" + struct.pack("<I", ERET).hex(),
            "instruction_size": 4,
            "operation": "exception_return",
            "attributes": {},
        }
    )
    expectations: dict[str, object] = {
        "fixture_classification": {
            "owned": True,
            "synthetic": True,
            "real_vulnerability": False,
            "affected_hardware_reproduction": False,
            "runtime_execution_evidence": False,
            "triggerability_demonstration": False,
        },
        "architecture": "AARCH64",
        "format": "ELF64 little-endian AArch64",
        "decoder_profile_id": (
            "phase10d_aarch64_static_semantic_decoder_audited_partial_v1"
        ),
        "expected_facts": expected_facts,
        "expected_fact_count": len(expected_facts),
        "distractor_instruction_count": sum(
            operation is None for _word, operation, _attributes in INSTRUCTIONS
        ),
        "non_executable_copies": {
            "section": ".data",
            "address": hex(DATA_ADDRESS),
            "file_offset": hex(DATA_OFFSET),
            "separated_words": [f"0x{word:08x}" for word in data_words],
        },
    }
    return bytes(image), expectations


def main() -> None:
    """Write the ELF, hash manifest and semantic expectations."""

    fixture_directory = Path(__file__).resolve().parent
    binary, expectations = build_elf()
    binary_path = fixture_directory / "aarch64_generic_static_semantic_v1.elf"
    binary_path.write_bytes(binary)
    digest = hashlib.sha256(binary).hexdigest()
    expectations["artifact_sha256"] = digest
    (fixture_directory / "SHA256SUMS").write_text(
        f"{digest}  {binary_path.name}\n",
        encoding="ascii",
    )
    (fixture_directory / "expected_static_semantics.json").write_text(
        json.dumps(expectations, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {binary_path.name} ({len(binary)} bytes, sha256={digest})")


if __name__ == "__main__":
    main()
