"""Closed local lexical profiles shared by detached IR validation and ingestion.

No filesystem access or processor decoding. Widths describe printed fields,
not a claim of complete architectural state or universal simulator formats.
"""

import csv
import re


CSV_HEADER = "pc,instr,gpr,csr,binary,mode,instr_str,operand,pad,mstatus,frm,fflags,mcause,scause,medeleg,mcounteren,scounteren"
RTL_HEADER = "HartID mode PC INSTR WDATA COV"
FIELD_NAMES = ("mstatus", "frm", "fflags", "mcause", "scause", "medeleg", "mcounteren", "scounteren")
FIELD_WIDTHS = (64, 3, 5, 8, 8, 64, 32, 32)
RTL_FIELD_INDICES = (5, 27, 26, 6, 7, 8, 9, 10)


def printable_line(line: str) -> None:
    if not line or any(not 32 <= ord(char) <= 126 for char in line):
        raise ValueError("profile requires a nonempty printable ASCII record")


def hex_token(token: str, bits: int, *, prefix: bool = False, exact: bool = True) -> None:
    digits = token[2:] if prefix and token.startswith("0x") else token
    if prefix and not token.startswith("0x"):
        raise ValueError("explicit lowercase hexadecimal prefix required")
    if re.fullmatch(r"[0-9a-f]+", digits) is None:
        raise ValueError("lowercase hexadecimal token required")
    if (exact and len(digits) != (bits + 3) // 4) or len(digits) > (bits + 3) // 4:
        raise ValueError("hexadecimal token width mismatch")
    if int(digits, 16).bit_length() > bits:
        raise ValueError("hexadecimal token exceeds printed field width")


def csv_columns(line: str) -> tuple[str, ...]:
    printable_line(line)
    # strict=True alone permits quotes inside unquoted fields. Close that gap.
    if re.fullmatch(r'(?:[^",\r\n]*|"(?:[^"\r\n]|"")*")(?:,(?:[^",\r\n]*|"(?:[^"\r\n]|"")*"))*', line) is None:
        raise ValueError("invalid CSV quoting")
    values = tuple(next(csv.reader([line], strict=True)))
    if len(values) != 17:
        raise ValueError("confirmed CSV profile requires exactly 17 columns")
    hex_token(values[0], 64)
    hex_token(values[4], 32)
    if values[5] not in ("", "0", "1", "2", "3"):
        raise ValueError("invalid mode token")
    if not values[1] or not values[6]:
        raise ValueError("instruction mnemonic/text required")
    for token, width in zip(values[9:], FIELD_WIDTHS, strict=True):
        if token:  # Absence stays absent; it is never a zero state.
            hex_token(token, width, exact=False)
    return values


_ISA_PREFIX = r"core +(?P<hart>[0-9]+): "
_PC_BITS = r"(?P<pc>0x[0-9a-f]{16}) \((?P<bits>0x[0-9a-f]{8})\)"
_ISA_PATTERNS = (
    ("DESCRIPTION", re.compile(_ISA_PREFIX + _PC_BITS + r" \[(?P<states>[^\[\]]+)\] (?P<text>\S.*)")),
    ("COMMIT", re.compile(_ISA_PREFIX + r"(?P<mode>[0-3]) " + _PC_BITS + r"(?P<updates>.*)")),
    ("EXCEPTION", re.compile(_ISA_PREFIX + r"exception (?P<exception>trap_[a-z_]+), epc (?P<pc>0x[0-9a-f]{16})")),
    ("LABEL_OR_CONTEXT", re.compile(_ISA_PREFIX + r">>>> +(?P<label>[A-Za-z_.$][A-Za-z0-9_.$]*)")),
    ("OTHER_SUPPORTED", re.compile(_ISA_PREFIX + r" +tval (?P<tval>0x[0-9a-f]{16})")),
)
_UPDATE = re.compile(r" +(?:(?:[xf] ?(?:[0-9]|[12][0-9]|3[01])|c[0-9]+_[a-z][a-z0-9_]*) 0x[0-9a-f]{16}|mem 0x[0-9a-f]{16}(?: 0x[0-9a-f]{1,16})?)")


def isa_log_fields(line: str) -> tuple[str, dict[str, str]]:
    printable_line(line)
    for kind, pattern in _ISA_PATTERNS:
        match = pattern.fullmatch(line)
        if match is None:
            continue
        fields = match.groupdict()
        if kind == "DESCRIPTION":
            states = fields["states"].split(",")
            if len(states) != 9:
                raise ValueError("description requires nine lexical state tokens")
            hex_token(states[0], 64, prefix=True, exact=False)
            for token, width in zip(states[1:], (*FIELD_WIDTHS[1:], 32), strict=True):
                hex_token(token, width, exact=False)
        if kind == "COMMIT":
            updates = fields["updates"]
            if "".join(item.group() for item in _UPDATE.finditer(updates)) != updates:
                raise ValueError("unsupported commit update structure")
        return kind, fields
    raise ValueError("unsupported ISA log record structure")


# Indices refer to the lexical NORMAL layout with EXCEPTION marker removed.
_RTL_WIDTHS = (
    64, 8, 8, 64, 32, 32, 32,  # 5..11
    64, 64, 64, 64, 64, 40, 32, 40, 40, 40, 39, 4, 44,
    5, 3, 8, 3, 64, 64, 64, 64, 16, 64, 32, 64, 64, 64,
    *((8,) * 8), *((30,) * 8), *((64,) * 63),
)


def rtl_tokens(line: str, kind: str) -> tuple[str, ...]:
    printable_line(line)
    tokens = line.split()
    if kind == "RTL_EXCEPTION":
        if len(tokens) != 120 or tokens[13] != "EXCEPTION":
            raise ValueError("malformed RTL exception record")
        del tokens[13]
    elif kind != "RTL_NORMAL" or len(tokens) != 119:
        raise ValueError("malformed RTL normal record")
    if tokens[0] not in ("0", "1") or tokens[1] not in ("0", "1", "2", "3"):
        raise ValueError("invalid printed hart/mode")
    hex_token(tokens[2], 40, prefix=True)
    hex_token(tokens[3], 32, prefix=True)
    hex_token(tokens[4], 64, prefix=True)
    if re.fullmatch(r"[0-9]{1,10}", tokens[12]) is None or int(tokens[12]) >= 1 << 30:
        raise ValueError("invalid io_covSum token")
    state_tokens = tokens[5:12] + tokens[13:]
    for token, width in zip(state_tokens, _RTL_WIDTHS, strict=True):
        hex_token(token, width)
    return tuple(tokens)


def delayed_fields(line: str) -> dict[str, str]:
    printable_line(line)
    match = re.fullmatch(r"DELAYED (?P<bank>[rf])(?P<index>[0-9]|[12][0-9]|3[01])=(?P<value>[0-9a-f]{16})(?: (?P<flags>[0-9a-f]{2}))?", line)
    if match is None:
        raise ValueError("malformed DELAYED record")
    fields = match.groupdict()
    if (fields["bank"] == "f") != (fields["flags"] is not None):
        raise ValueError("DELAYED flags do not match printed bank")
    if fields["flags"] is not None:
        hex_token(fields["flags"], 5)
    return {key: value for key, value in fields.items() if value is not None}
