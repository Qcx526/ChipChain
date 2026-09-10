"""Benign hand-built hardware-test ELF/SI/trace fixtures, not real findings."""

import struct
from hashlib import sha256

import pytest

from chipchain.core import Architecture, ArtifactProvenance, HardwareTargetIdentity, ProcessorFuzzArtifact
from chipchain.adapters.processorfuzz import parse_processorfuzz_si, map_processorfuzz_si
from chipchain.adapters.hardware_case import parse_isa_csv, parse_rtl_log
from chipchain.anchors import parse_hardware_test_elf


class SyntheticHardwareCase:
    """Independent ELF-layout fixtures; no external files or tool invocation."""

    @staticmethod
    def elf(*, symbols=None, loads=None, word="00000013"):
        symbols = [("_p0", 0x200, 1), ("_l0", 0x204, 1), ("_s0", 0x208, 1)] if symbols is None else symbols
        loads = [(0x200, 0x100, 12, 32)] if loads is None else loads
        data = bytearray(0x580)
        data[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
        struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 243, 1, 0x200, 64, 0x400, 0, 64, 56, len(loads), 64, 5, 4)
        for index, (address, offset, file_size, memory_size) in enumerate(loads):
            struct.pack_into("<IIQQQQQQ", data, 64 + index * 56, 1, 5, offset, address, address, file_size, memory_size, 1)
        data[0x100:0x10c] = int(word, 16).to_bytes(4, "little") * 3
        names = b"\x00"
        records = [b"\x00" * 24]
        for name, address, section in symbols:
            records.append(struct.pack("<IBBHQQ", len(names), 0, 0, section, address, 0))
            names += name.encode() + b"\x00"
        symtab = b"".join(records)
        assert len(symtab) <= 0x100 and len(names) <= 0x100
        data[0x180:0x180 + len(symtab)] = symtab
        data[0x280:0x280 + len(names)] = names
        shnames = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
        data[0x380:0x380 + len(shnames)] = shnames
        sections = [
            (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (1, 1, 6, 0x200, 0x100, 12, 0, 0, 4, 0),
            (7, 2, 0, 0, 0x180, len(symtab), 3, len(records), 8, 24),
            (15, 3, 0, 0, 0x280, len(names), 0, 0, 1, 0),
            (23, 3, 0, 0, 0x380, len(shnames), 0, 0, 1, 0),
        ]
        for index, values in enumerate(sections):
            struct.pack_into("<IIQQQQIIQQ", data, 0x400 + index * 64, *values)
        return bytes(data)

    @staticmethod
    def si():
        return parse_processorfuzz_si(
            b"p-m\n\n_p0:    addi x1, zero, 0\n        addi x2, x1, 1\n_l0:    addi x3, zero, 0\n_s0:    fence\ndata:\n0000000000000000\n"
        )

    @staticmethod
    def csv(pcs=(0x200, 0x204, 0x208), word="00000013", state="0"):
        header = "pc,instr,gpr,csr,binary,mode,instr_str,operand,pad,mstatus,frm,fflags,mcause,scause,medeleg,mcounteren,scounteren"
        lines = [header]
        for pc in pcs:
            lines.append(",".join([f"{pc:016x}", "nop", "", "", word, "3", "nop", "", "", state, "0", "00", "00", "00", "00000000", "00000000", "00000000"]))
        return parse_isa_csv(("\r\n".join(lines) + "\r\n").encode(), architecture=Architecture.RISC_V)

    @staticmethod
    def rtl(pcs=(0x200, 0x204, 0x208), word="00000013", state=0, delayed=False):
        widths = [64, 8, 8, 64, 32, 32, 32, None, 64, 64, 64, 64, 64,
                  40, 32, 40, 40, 40, 39, 4, 44, 5, 3, 8, 3, 64, 64, 64,
                  64, 16, 64, 32, 64, 64, 64] + [8] * 8 + [30] * 8 + [64] * 63
        rows = ["HartID mode PC INSTR WDATA COV"]
        for pc in pcs:
            tokens = ["0", "3", f"0x{pc:010x}", "0x" + word, "0x0000000000000000"]
            tokens += ["0" * ((width + 3) // 4) if width is not None else "7" for width in widths]
            tokens[5] = f"{state:016x}"
            rows.append(" ".join(tokens))
        if delayed:
            rows.append("DELAYED r1=0000000000000000")
        return parse_rtl_log(("\n".join(rows) + "\n").encode(), architecture=Architecture.RISC_V)

    @staticmethod
    def fragment(raw):
        source = ProcessorFuzzArtifact(hardware_target=HardwareTargetIdentity(
            target_id="synthetic-hardware-experiment", architecture=Architecture.RISC_V, hardware_model="Synthetic"),
            provenance=ArtifactProvenance(artifact_id="synthetic-si", artifact_sha256=sha256(raw.exact_bytes()).hexdigest(),
                architecture=Architecture.RISC_V, source_kind="synthetic-format-only", producer_profile_id="synthetic-profile"))
        return map_processorfuzz_si(raw, source)


@pytest.fixture
def hardware_case():
    return SyntheticHardwareCase()


@pytest.fixture
def elf_snapshot(hardware_case):
    data = hardware_case.elf()
    return parse_hardware_test_elf(data), data
