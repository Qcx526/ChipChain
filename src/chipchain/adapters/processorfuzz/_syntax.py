"""Confirmed-case lexical rules only, not RISC-V instruction effect semantics."""

import re

from chipchain.adapters.processorfuzz.errors import ProcessorFuzzSIParseError


PARSER_PROFILE_ID = "processorfuzz_si_confirmed_v1"
# Only the symbolic CSR vocabulary observed in the confirmed source. This does
# not assert that any particular processor implements these registers.
CSR_NAMES = frozenset({
    "fcsr", "mcause", "mepc", "mip", "mstatus", "mtval", "pmpaddr1", "pmpaddr2",
    "pmpaddr6", "pmpaddr7", "pmpcfg0", "scause", "sepc", "sip", "sstatus", "uepc",
})
_BARE_MNEMONICS = frozenset({"fence", "fence.i", "mret", "sret", "uret"})
_REGISTER = r"[xf](?:[0-9]|[12][0-9]|3[01])"
_LABEL = r"_[pls](?:0|[1-9][0-9]*)"


def register_kind(token: str) -> str | None:
    """Classify literal tokens without alias rewriting or read/write inference."""

    if re.fullmatch(_REGISTER, token):
        return "gpr" if token.startswith("x") else "floating_point"
    if token == "zero":
        return "gpr"
    if token in CSR_NAMES:
        return "system"
    return None


def _operand(token: str) -> bool:
    return bool(
        register_kind(token)
        or re.fullmatch(r"-?[0-9]+|0x[0-9a-f]+", token)
        or re.fullmatch(_LABEL, token)
        or re.fullmatch(r"d_(?:0|[1-9][0-9]*)_(?:0|[1-9][0-9]*)|pt[0-9]+", token)
        or re.fullmatch(r"(?:-?[0-9]+)?\(x(?:[0-9]|[12][0-9]|3[01])\)", token)
        or token in {"rne", "rtz", "rdn", "rup", "rmm", "dyn"}
    )


def _body(text: str) -> tuple[str, tuple[str, ...]]:
    parts = text.split(maxsplit=1)
    if not parts or re.fullmatch(r"[a-z][a-z0-9]*(?:\.[a-z0-9]+)*", parts[0]) is None:
        raise ProcessorFuzzSIParseError("instruction: malformed mnemonic")
    mnemonic = parts[0]
    if len(parts) == 1:
        if mnemonic not in _BARE_MNEMONICS:
            raise ProcessorFuzzSIParseError("instruction: unsupported bare source form")
        return mnemonic, ()
    operands = tuple(part.strip(" ") for part in parts[1].split(","))
    if not all(_operand(token) for token in operands):
        raise ProcessorFuzzSIParseError("instruction: malformed or unsupported operand")
    if mnemonic in _BARE_MNEMONICS:
        raise ProcessorFuzzSIParseError("instruction: unsupported operand-bearing source form")
    return mnemonic, operands


def instruction_fields(line: str) -> tuple[str | None, str, tuple[str, ...], str | None]:
    """Read one exact line; only column 51 can hold the profile's trailer.

    A comma awaiting its operand takes precedence over the trailer column. A
    numeric operand is never removed merely because its spelling is 0000.
    No labels, instructions or pseudo-instructions are executed or expanded.
    """

    if not line or any(ord(c) < 32 or ord(c) > 126 for c in line):
        raise ProcessorFuzzSIParseError("instruction: invalid text")
    label = None
    if line.startswith("        "):
        body_start = 8
    else:
        match = re.match(rf"^({_LABEL}): +", line)
        if match is None:
            raise ProcessorFuzzSIParseError("instruction: malformed label or indentation")
        label, body_start = match[1], match.end()
    text = line[body_start:].rstrip(" ")
    trailing = None
    if len(line) >= 54 and line[50:].rstrip(" ") == "0000" and line[48:50] == "  ":
        prefix = line[body_start:50].rstrip(" ")
        if not prefix.endswith(","):
            # The prefix must independently be a complete source form. In
            # particular, an ambiguous single numeric operand is not stripped.
            mnemonic, operands = _body(prefix)
            return label, mnemonic, operands, "0000"
    mnemonic, operands = _body(text)
    return label, mnemonic, operands, trailing
