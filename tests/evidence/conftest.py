"""Benign synthetic, format-only fixtures; not a real hardware finding."""

import csv
import io

import pytest

from chipchain.core import Architecture, ProgramAddress
from chipchain.adapters.hardware_case import parse_isa_csv, parse_rtl_log
from chipchain.evidence import AlignmentScope, ComparableField, align_common_program


class SyntheticCase:
    """Independent print-layout fixture builder, with no real-case input reads."""

    header = "pc,instr,gpr,csr,binary,mode,instr_str,operand,pad,mstatus,frm,fflags,mcause,scause,medeleg,mcounteren,scounteren"
    rtl_header = "HartID mode PC INSTR WDATA COV"

    @staticmethod
    def csv_row(pc=0x200, encoding="00000013", mode="3", mstatus="1"):
        return [f"{pc:016x}", "nop", "f0:0000000000000001;mstatus:1", "", encoding, mode,
                "nop", "", "", mstatus, "0", "00", "00", "00", "00000000", "00000000", "00000000"]

    def csv(self, rows=None):
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, lineterminator="\r\n")
        writer.writerow(self.header.split(","))
        writer.writerows([self.csv_row()] if rows is None else rows)
        return stream.getvalue().encode("ascii")

    @staticmethod
    def rtl_row(pc=0x200, encoding="00000013", mstatus=1, cov=10, exception=False, sentinel=False):
        # Widths independently transcribed from the audited local print layout.
        widths = [64, 8, 8, 64, 32, 32, 32, None, 64, 64, 64, 64, 64,
                  40, 32, 40, 40, 40, 39, 4, 44, 5, 3, 8, 3, 64, 64, 64,
                  64, 16, 64, 32, 64, 64, 64] + [8] * 8 + [30] * 8 + [64] * 63
        tokens = ["0", "3", f"0x{pc:010x}", "0x" + encoding,
                  "0x00000000deadbeef" if sentinel else "0x0000000000000000"]
        tokens += ["0" * ((width + 3) // 4) if width is not None else str(cov) for width in widths]
        tokens[5] = f"{mstatus:016x}"
        assert len(tokens) == 119
        if exception:
            tokens.insert(13, "EXCEPTION")
        return " ".join(tokens)

    def rtl(self, rows=None):
        return (self.rtl_header + "\n" + "\n".join([self.rtl_row()] if rows is None else rows) + "\n").encode("ascii")

    @staticmethod
    def isa_log():
        return (
            "core   0: >>>>  harmless_label\n"
            "core   0: 0x0000000000000200 (0x00000013) [0x1,0,00,00,00,00000000,00000000,00000000,00000000] nop\n"
            "core   0: 3 0x0000000000000200 (0x00000013)\n"
            "core   0: 3 0x0000000000000204 (0x00000013) x 1 0x0000000000000001 f 2 0x0000000000000002 c2_frm 0x0000000000000000 mem 0x0000000000000300 0x01\n"
            "core   0: exception trap_illegal_instruction, epc 0x0000000000000208\n"
            "core   0:           tval 0x0000000000000000\n"
        ).encode("ascii")

    @staticmethod
    def signature():
        return ("\n".join(f"{index % 4:032x}" for index in range(254)) + "\n").encode("ascii")

    def alignment(self, *, rows=None, rtl_rows=None, fields=None):
        isa = parse_isa_csv(self.csv(rows), architecture=Architecture.RISC_V)
        rtl = parse_rtl_log(self.rtl(rtl_rows), architecture=Architecture.RISC_V)
        scope = AlignmentScope(isa_source=isa.source, rtl_source=rtl.source,
                               common_start_pc=ProgramAddress(value="0x200"),
                               comparable_fields=tuple(ComparableField) if fields is None else fields)
        return align_common_program(scope, isa, rtl)


@pytest.fixture
def synthetic_case():
    return SyntheticCase()
