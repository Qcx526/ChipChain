"""Generate a deterministic owned synthetic AArch64 semantic fixture.

The generator emits only isolated benign instruction examples and separated
non-executable byte copies. It is independent of a compiler or cross-toolchain
and does not create a CVE trigger/reproducer sequence.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct


TEXT_ADDRESS = 0x0000000000400000
DATA_ADDRESS = 0x0000000000401000
TEXT_OFFSET = 0x1000
DATA_OFFSET = 0x2000
RET = 0xD65F03C0


@dataclass(frozen=True)
class Function:
    """One isolated symbol-backed function with audited A64 words."""

    name: str
    words: tuple[int, ...]


FUNCTIONS = (
    Function("owned_load_example", (0xF9400020, RET)),
    Function("owned_store_exclusive_example", (0xC8007C41, RET)),
    Function("owned_par_el1_read_example", (0xD5387400, RET)),
    Function(
        "owned_near_miss_examples",
        (
            0xF9000020,  # STR X0, [X1] -- ordinary store
            0xC85F7C41,  # LDXR X1, [X2] -- load-exclusive
            0xD5187400,  # MSR PAR_EL1, X0 -- system-register write
            0xD5386000,  # MRS X0, FAR_EL1 -- wrong system register
            0xF8400020,  # LDUR X0, [X1] -- unsupported load family in v1
            RET,
        ),
    ),
)
EXPECTED_SEMANTICS = (
    ("owned_load_example", 0, "memory_load", "0xf9400020", None),
    (
        "owned_store_exclusive_example",
        0,
        "store_exclusive",
        "0xc8007c41",
        None,
    ),
    (
        "owned_par_el1_read_example",
        0,
        "system_register_read",
        "0xd5387400",
        "PAR_EL1",
    ),
)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build_elf() -> tuple[bytes, dict[str, object]]:
    """Return deterministic ELF64 bytes and extractor expectations."""

    text = bytearray()
    function_layout: list[dict[str, object]] = []
    for function in FUNCTIONS:
        address = TEXT_ADDRESS + len(text)
        encoded = b"".join(struct.pack("<I", word) for word in function.words)
        function_layout.append(
            {
                "name": function.name,
                "address": address,
                "size": len(encoded),
                "words": [f"0x{word:08x}" for word in function.words],
            }
        )
        text.extend(encoded)

    # Exact semantic bytes are present outside executable code, but separators
    # prevent this data from representing an instruction sequence.
    data_words = (0xF9400020, 0, 0xC8007C41, 0, 0xD5387400)
    data = b"".join(struct.pack("<I", word) for word in data_words)

    string_table = bytearray(b"\x00")
    name_offsets: dict[str, int] = {}
    for function in FUNCTIONS:
        name_offsets[function.name] = len(string_table)
        string_table.extend(function.name.encode("ascii") + b"\x00")

    symbol_table = bytearray(24)
    for function, layout in zip(FUNCTIONS, function_layout, strict=True):
        symbol_table.extend(
            struct.pack(
                "<IBBHQQ",
                name_offsets[function.name],
                0x12,  # STB_GLOBAL | STT_FUNC
                0,
                1,  # .text
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
        2,  # ET_EXEC
        183,  # EM_AARCH64
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
                5,  # PF_R | PF_X
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
                6,  # PF_R | PF_W, deliberately non-executable
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
            "<IIQQQQIIQQ",
            section_name_offsets[".data"],
            1,
            0x3,  # SHF_ALLOC | SHF_WRITE
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

    by_name = {str(item["name"]): item for item in function_layout}
    expected_facts = []
    for function_name, word_index, event_kind, word, system_register in (
        EXPECTED_SEMANTICS
    ):
        layout = by_name[function_name]
        address = int(layout["address"]) + word_index * 4
        expected_facts.append(
            {
                "function": function_name,
                "function_address": f"0x{int(layout['address']):016x}",
                "instruction_address": f"0x{address:016x}",
                "instruction_word": word,
                "event_kind": event_kind,
                "system_register": system_register,
                "memory_type_resolution": (
                    "requires_objective_translation_context"
                    if event_kind == "memory_load"
                    else "not_applicable"
                ),
            }
        )

    expectations: dict[str, object] = {
        "fixture_classification": {
            "owned": True,
            "synthetic": True,
            "real_vulnerability": False,
            "affected_hardware_reproduction": False,
            "triggerability_demonstration": False,
        },
        "architecture": "AARCH64",
        "format": "ELF64 little-endian AArch64",
        "entry_point": f"0x{TEXT_ADDRESS:016x}",
        "expected_facts": expected_facts,
        "expected_fact_count": len(expected_facts),
        "expected_predicate_candidate_count": len(expected_facts) * 2,
        "near_miss_function": by_name["owned_near_miss_examples"],
        "non_executable_copies": {
            "section": ".data",
            "address": f"0x{DATA_ADDRESS:016x}",
            "file_offset": f"0x{DATA_OFFSET:016x}",
            "separated_words": [f"0x{word:08x}" for word in data_words],
        },
    }
    return bytes(image), expectations


def main() -> None:
    """Write the ELF, hash manifest, and extractor expectations."""

    fixture_directory = Path(__file__).resolve().parent
    binary, expectations = build_elf()
    binary_path = fixture_directory / "a_profile_static_semantic_a64.elf"
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
