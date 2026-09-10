"""Narrow ELF64 LE RISC-V hardware-test-program view, never client firmware.

No decoding, tool execution or file I/O. A serialized view is a declaration:
lookup and anchor services always reproduce it from the supplied exact bytes.
"""

from hashlib import sha256
import struct
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from chipchain.core import Architecture, ProgramAddress
from chipchain.anchors.base import AnchorError, AnchorModel, Ordinal, Sha256, UInt64


def _range(offset: int, size: int, limit: int) -> None:
    if offset < 0 or size < 0 or offset >= 1 << 64 or size >= 1 << 64 or offset + size > min(limit, 1 << 64):
        raise AnchorError("range exceeds exact file or unsigned address space")


class HardwareTestProgramELFSource(AnchorModel):
    """Hardware-experiment artifact identity, with no client/firmware binding."""

    _namespace = "v2-hardware-test-elf-source-v1"
    artifact_sha256: Sha256
    byte_length: Annotated[int, Field(strict=True, ge=64, lt=1 << 64)]
    architecture: Literal[Architecture.RISC_V] = Architecture.RISC_V
    artifact_kind: Literal["HARDWARE_TEST_PROGRAM_ELF"] = "HARDWARE_TEST_PROGRAM_ELF"
    profile_id: Literal["confirmed_riscv_elf64_le_v1"] = "confirmed_riscv_elf64_le_v1"


class ELFLoadSegment(AnchorModel):
    """A PT_LOAD mapping; virtual address is not physical address or MMIO."""

    _namespace = "v2-hardware-test-elf-load-v1"
    program_header_ordinal: Ordinal
    virtual_address: UInt64
    file_offset: UInt64
    file_size: UInt64
    memory_size: UInt64
    flags: Annotated[int, Field(strict=True, ge=0, le=7)]
    alignment: UInt64

    @model_validator(mode="after")
    def validate_range(self) -> Self:
        if self.file_size > self.memory_size:
            raise ValueError("LOAD file size exceeds memory size")
        _range(self.virtual_address, self.memory_size, 1 << 64)
        if self.alignment not in (0, 1):
            if self.alignment & (self.alignment - 1) or self.virtual_address % self.alignment != self.file_offset % self.alignment:
                raise ValueError("invalid LOAD alignment/congruence")
        return self


class ELFSection(AnchorModel):
    """Parsed section-table metadata; names do not assert source-language meaning."""

    _namespace = "v2-hardware-test-elf-section-v1"
    section_ordinal: Ordinal
    name: Annotated[str, Field(strict=True, pattern=r"^[ -~]*$")]
    section_type: Annotated[int, Field(strict=True, ge=0, lt=1 << 32)]
    flags: UInt64
    address: UInt64
    file_offset: UInt64
    size: UInt64
    link: Ordinal
    info: Ordinal
    alignment: UInt64
    entry_size: UInt64


class ELFSymbol(AnchorModel):
    """One .symtab occurrence, retaining table/index to expose duplicates."""

    _namespace = "v2-hardware-test-elf-symbol-v1"
    symbol_table_section: Ordinal
    symbol_ordinal: Ordinal
    name: Annotated[str, Field(strict=True, pattern=r"^[ -~]*$")]
    value: UInt64
    size: UInt64
    symbol_type: Annotated[int, Field(strict=True, ge=0, le=15)]
    binding: Annotated[int, Field(strict=True, ge=0, le=15)]
    other: Annotated[int, Field(strict=True, ge=0, le=255)]
    section_index: Annotated[int, Field(strict=True, ge=0, le=65535)]


class HardwareTestProgramELF(AnchorModel):
    """Small reproducible hardware-test ELF view, not an ImmutableFirmwareArtifact."""

    _namespace = "v2-hardware-test-program-elf-v1"
    contract: Literal["v2_hardware_test_program_elf_v1"] = "v2_hardware_test_program_elf_v1"
    source: HardwareTestProgramELFSource
    entry_address: ProgramAddress
    load_segments: tuple[ELFLoadSegment, ...]
    sections: tuple[ELFSection, ...]
    symbols: tuple[ELFSymbol, ...]

    @model_validator(mode="after")
    def validate_structure(self) -> Self:
        if int(self.entry_address.value, 16) >= 1 << 64:
            raise ValueError("entry exceeds ELF64 address width")
        if not self.load_segments or not self.sections:
            raise ValueError("local profile requires LOAD and section tables")
        indices = tuple(segment.program_header_ordinal for segment in self.load_segments)
        if indices != tuple(sorted(set(indices))):
            raise ValueError("LOAD records must preserve unique header order")
        for segment in self.load_segments:
            _range(segment.file_offset, segment.file_size, self.source.byte_length)
        for index, section in enumerate(self.sections):
            if section.section_ordinal != index or section.link >= len(self.sections):
                raise ValueError("section index/link out of range")
            _range(section.address, section.size, 1 << 64)
            if section.section_type != 8:  # SHT_NOBITS has no file payload.
                _range(section.file_offset, section.size, self.source.byte_length)
            if section.alignment and section.alignment & (section.alignment - 1):
                raise ValueError("section alignment must be a power of two")
        tables = tuple(section for section in self.sections if section.section_type == 2)
        if not tables:
            raise ValueError("local profile requires a static symbol table")
        keys = []
        for table in tables:
            if table.entry_size != 24 or not table.size or table.size % 24 or self.sections[table.link].section_type != 3:
                raise ValueError("malformed symtab entry size or string table link")
            if table.info > table.size // 24:
                raise ValueError("symtab local-symbol boundary out of range")
            keys.extend((table.section_ordinal, index) for index in range(table.size // 24))
        if [(symbol.symbol_table_section, symbol.symbol_ordinal) for symbol in self.symbols] != keys:
            raise ValueError("symbols must preserve complete table/occurrence order")
        for symbol in self.symbols:
            if symbol.section_index == 0xffff or (symbol.section_index < 0xff00 and symbol.section_index >= len(self.sections)):
                raise ValueError("unsupported or invalid symbol section index")
        return self


def _string(data: bytes, offset: int) -> str:
    if offset >= len(data):
        raise AnchorError("string table offset out of range")
    end = data.find(b"\x00", offset)
    if end < 0:
        raise AnchorError("unterminated string table entry")
    value = data[offset:end]
    if any(byte < 32 or byte > 126 for byte in value):
        raise AnchorError("unsupported non-printable symbol/section name")
    return value.decode("ascii")


def parse_hardware_test_elf(data: bytes, *, expected_sha256: str | None = None) -> HardwareTestProgramELF:
    """Parse only exact ELF64 LE RISC-V ET_EXEC bytes; never execute a binary."""

    if type(data) is not bytes:
        raise AnchorError("immutable ELF bytes required")
    digest = sha256(data).hexdigest()
    if expected_sha256 is not None and expected_sha256 != digest:
        raise AnchorError("ELF SHA differs from expected source")
    try:
        return _parse(data, digest)
    except (ValueError, struct.error, IndexError):
        raise AnchorError("unsupported or malformed hardware-test ELF snapshot") from None


def _parse(data: bytes, digest: str) -> HardwareTestProgramELF:
    _range(0, 64, len(data))
    if data[:7] != b"\x7fELF\x02\x01\x01" or data[7] != 0 or any(data[8:16]):
        raise AnchorError("unsupported ELF identification/profile")
    (etype, machine, version, entry, phoff, shoff, _flags,
     ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    if (etype, machine, version, ehsize, phentsize, shentsize) != (2, 243, 1, 64, 56, 64):
        raise AnchorError("unsupported ELF header")
    if not 0 < phnum < 0xffff or not 0 < shnum < 0xff00 or not 0 < shstrndx < shnum:
        raise AnchorError("extended/missing ELF table indices unsupported")
    if phoff < 64 or shoff < 64:
        raise AnchorError("ELF tables overlap fixed header")
    _range(phoff, phnum * 56, len(data))
    _range(shoff, shnum * 64, len(data))
    if max(phoff, shoff) < min(phoff + phnum * 56, shoff + shnum * 64):
        raise AnchorError("ELF header tables overlap")
    loads = []
    for index in range(phnum):
        ptype, flags, offset, vaddr, _paddr, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", data, phoff + index * 56)
        _range(offset, filesz, len(data))
        if ptype == 1:
            loads.append(ELFLoadSegment(program_header_ordinal=index, virtual_address=vaddr,
                file_offset=offset, file_size=filesz, memory_size=memsz, flags=flags, alignment=align))
    sections_raw = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * 64) for index in range(shnum)]
    if any(sections_raw[0]):
        raise AnchorError("section zero/extended numbering unsupported")
    for values in sections_raw:
        if values[1] != 8:
            _range(values[4], values[5], len(data))
    shstrings = sections_raw[shstrndx]
    if shstrings[1] != 3:
        raise AnchorError("section-name table must be STRTAB")
    names = data[shstrings[4]:shstrings[4] + shstrings[5]]
    if not names or names[0] != 0 or names[-1] != 0:
        raise AnchorError("malformed section-name string table")
    sections = tuple(ELFSection(section_ordinal=i, name=_string(names, v[0]), section_type=v[1],
        flags=v[2], address=v[3], file_offset=v[4], size=v[5], link=v[6], info=v[7], alignment=v[8], entry_size=v[9])
        for i, v in enumerate(sections_raw))
    symbols = []
    for table in sections:
        if table.section_type != 2:
            continue
        if table.entry_size != 24 or not table.size or table.size % 24 or table.link >= shnum:
            raise AnchorError("malformed static symbol table")
        linked = sections[table.link]
        if linked.section_type != 3:
            raise AnchorError("symbol names require a string table")
        strings = data[linked.file_offset:linked.file_offset + linked.size]
        if not strings or strings[0] != 0 or strings[-1] != 0:
            raise AnchorError("malformed symbol string table")
        for index in range(table.size // 24):
            name, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", data, table.file_offset + index * 24)
            if index == 0 and (name, info, other, shndx, value, size) != (0, 0, 0, 0, 0, 0):
                raise AnchorError("symbol zero must be undefined/empty")
            symbols.append(ELFSymbol(symbol_table_section=table.section_ordinal, symbol_ordinal=index,
                name=_string(strings, name), value=value, size=size, symbol_type=info & 15,
                binding=info >> 4, other=other, section_index=shndx))
    return HardwareTestProgramELF(source=HardwareTestProgramELFSource(artifact_sha256=digest, byte_length=len(data)),
        entry_address=ProgramAddress(value=hex(entry)), load_segments=tuple(loads), sections=sections, symbols=tuple(symbols))


def revalidate_hardware_test_elf(view: HardwareTestProgramELF, data: bytes) -> HardwareTestProgramELF:
    """Reproduce every retained parsed field, not merely a caller-claimed SHA."""

    snapshot = HardwareTestProgramELF.model_validate(view)
    actual = parse_hardware_test_elf(data, expected_sha256=snapshot.source.artifact_sha256)
    if actual != snapshot:
        raise AnchorError("ELF view is not reproducible from exact supplied bytes")
    return actual


def _lookup(view: HardwareTestProgramELF, data: bytes, address: ProgramAddress, size: int) -> bytes:
    if type(size) is not int or size <= 0:
        raise AnchorError("lookup size must be a positive integer")
    address = ProgramAddress.model_validate(address)
    start = int(address.value, 16)
    _range(start, size, 1 << 64)
    # Reject ANY LOAD overlap, including a competing zero-fill memory range.
    # A BSS mapping must not be silently hidden by another file-backed mapping.
    candidates = [segment for segment in view.load_segments if segment.memory_size and
        start < segment.virtual_address + segment.memory_size and segment.virtual_address < start + size]
    if len(candidates) != 1:
        raise AnchorError("no unique file-backed LOAD mapping")
    segment = candidates[0]
    if not segment.virtual_address <= start or start + size > segment.virtual_address + segment.file_size:
        raise AnchorError("read crosses file-backed LOAD boundary")
    offset = segment.file_offset + start - segment.virtual_address
    _range(offset, size, len(data))
    return data[offset:offset + size]


def read_elf_file_backed_bytes(view: HardwareTestProgramELF, data: bytes, *, address: ProgramAddress, size: int) -> bytes:
    """Recheck exact ELF then read a unique file-backed virtual range; never BSS."""

    return _lookup(revalidate_hardware_test_elf(view, data), data, address, size)
