"""Synthetic hardware-test ELF parsing/lookup, not client firmware analysis."""

from hashlib import sha256
import struct

import pytest
from pydantic import ValidationError

from chipchain.core import ProgramAddress
from chipchain.anchors import (
    AnchorError, HardwareTestProgramELF, parse_hardware_test_elf,
    read_elf_file_backed_bytes, revalidate_hardware_test_elf,
)


def test_exact_hardware_test_elf_and_roundtrip(elf_snapshot):
    view, data = elf_snapshot
    assert view.source.artifact_kind == "HARDWARE_TEST_PROGRAM_ELF"
    assert view.source.artifact_sha256 == sha256(data).hexdigest()
    assert view.source.byte_length == len(data)
    assert view.entry_address.value == "0x200"
    assert [symbol.name for symbol in view.symbols] == ["", "_p0", "_l0", "_s0"]
    assert len(view.load_segments) == 1
    assert HardwareTestProgramELF.model_validate_json(view.model_dump_json()).id == view.id
    assert revalidate_hardware_test_elf(view, data) == view
    assert parse_hardware_test_elf(data).id == view.id
    assert read_elf_file_backed_bytes(view, data, address=ProgramAddress(value="0x200"), size=4) == b"\x13\x00\x00\x00"


@pytest.mark.parametrize("offset,fmt,value", [
    (0, "4s", b"NOPE"), (4, "B", 1), (5, "B", 2), (6, "B", 0),
    (7, "B", 3), (8, "B", 1), (16, "H", 3), (18, "H", 62), (20, "I", 0),
    (32, "Q", 8), (32, "Q", (1 << 64) - 8), (40, "Q", 64),
    (52, "H", 63), (54, "H", 55), (56, "H", 0), (56, "H", 65535),
    (58, "H", 63), (60, "H", 0), (60, "H", 1000), (62, "H", 5),
    (64 + 8, "Q", 1 << 63), (64 + 32, "Q", 100), (64 + 40, "Q", 1),
    (64 + 16, "Q", (1 << 64) - 4), (64 + 48, "Q", 3),
    (0x400 + 64 + 24, "Q", 0xffff), (0x400 + 64 + 48, "Q", 3),
    (0x400 + 128 + 56, "Q", 23), (0x400 + 128 + 32, "Q", 25),
    (0x400 + 128 + 40, "I", 5), (0x400 + 128 + 40, "I", 1),
    (0x400 + 128 + 44, "I", 500),
    (0x400 + 256 + 4, "I", 1), (0x400 + 64, "I", 500),
    (0x180, "I", 1), (0x180 + 24, "I", 500),
    (0x180 + 24 + 6, "H", 50), (0x180 + 24 + 6, "H", 65535),
    (0x280, "B", 65), (0x280 + 1, "B", 255), (0x380, "B", 65),
])
def test_malformed_headers_tables_symbols_fail_closed(hardware_case, offset, fmt, value):
    data = bytearray(hardware_case.elf())
    struct.pack_into("<" + fmt, data, offset, value)
    with pytest.raises(AnchorError):
        parse_hardware_test_elf(bytes(data))


@pytest.mark.parametrize("length", [0, 4, 63, 100, 256, 0x450, 0x53f])
def test_truncated_elf(hardware_case, length):
    with pytest.raises(AnchorError):
        parse_hardware_test_elf(hardware_case.elf()[:length])


def test_unterminated_tables_and_symbols_rejected(hardware_case):
    original = hardware_case.elf()
    for start, length in ((0x280, 13), (0x380, 33)):
        data = bytearray(original)
        data[start:start + length] = b"A" * length
        with pytest.raises(AnchorError):
            parse_hardware_test_elf(bytes(data))


@pytest.mark.parametrize("address,size", [(0x20c, 1), (0x21c, 4), (0x20a, 4), (0x1fe, 4),
    (0x500, 4), ((1 << 64) - 1, 4), (1 << 64, 1), (0x200, 0), (0x200, -1), (0x200, True)])
def test_lookup_rejects_bss_boundaries_and_overflow(elf_snapshot, address, size):
    view, data = elf_snapshot
    with pytest.raises(ValueError):
        read_elf_file_backed_bytes(view, data, address=ProgramAddress(value=hex(address)), size=size)


@pytest.mark.parametrize("second_address", [0x200, 0x202])
def test_lookup_rejects_any_overlapping_file_mapping(hardware_case, second_address):
    data = hardware_case.elf(loads=[(0x200, 0x100, 12, 32), (second_address, 0x104, 4, 4)])
    view = parse_hardware_test_elf(data)
    with pytest.raises(AnchorError, match="unique"):
        read_elf_file_backed_bytes(view, data, address=ProgramAddress(value="0x200"), size=4)


def test_competing_bss_mapping_is_not_silently_ignored(hardware_case):
    data = hardware_case.elf(loads=[(0x200, 0x100, 12, 32), (0x200, 0x104, 0, 4)])
    view = parse_hardware_test_elf(data)
    with pytest.raises(AnchorError):
        read_elf_file_backed_bytes(view, data, address=ProgramAddress(value="0x200"), size=4)


def test_tampered_view_sha_bytes_and_length_cannot_supply_lookup(elf_snapshot):
    view, data = elf_snapshot
    for mutation in ("entry", "symbol", "load", "length", "sha"):
        payload = view.model_dump(mode="json")
        if mutation == "entry":
            payload["entry_address"]["value"] = "0x204"
        elif mutation == "symbol":
            payload["symbols"][1]["value"] = 0x204
        elif mutation == "load":
            payload["load_segments"][0]["file_offset"] += 4
        elif mutation == "length":
            payload["source"]["byte_length"] += 1
        else:
            payload["source"]["artifact_sha256"] = "0" * 64
        forged = HardwareTestProgramELF.model_validate(payload)
        with pytest.raises(AnchorError):
            read_elf_file_backed_bytes(forged, data, address=ProgramAddress(value="0x200"), size=4)
    with pytest.raises(AnchorError):
        revalidate_hardware_test_elf(view, data[:-1])
    altered = data[:-1] + bytes([data[-1] ^ 1])
    with pytest.raises(AnchorError):
        revalidate_hardware_test_elf(view, altered)
    with pytest.raises(AnchorError):
        parse_hardware_test_elf(bytearray(data))


def test_elf_is_detached_and_has_no_firmware_binding(elf_snapshot):
    view, _ = elf_snapshot
    original_id = view.id
    source = view.source
    segments = list(view.load_segments)
    retained = HardwareTestProgramELF.model_validate({**view.model_dump(), "source": source, "load_segments": segments})
    segments.clear()
    object.__setattr__(source, "artifact_sha256", "0" * 64)
    assert retained.id == original_id
    for key in ("firmware", "client_target", "immutable_firmware", "path", "timestamp", "run_id"):
        with pytest.raises(ValidationError):
            HardwareTestProgramELF.model_validate({**retained.model_dump(), key: "not-allowed"})
