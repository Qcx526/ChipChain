"""Pure bytes-to-raw structural parser; no filesystem or hardware metadata."""

from hashlib import sha256

from pydantic import ValidationError

from chipchain.adapters.processorfuzz._syntax import PARSER_PROFILE_ID, instruction_fields
from chipchain.adapters.processorfuzz.errors import ProcessorFuzzSIParseError, UnsupportedSIProfileError
from chipchain.adapters.processorfuzz.models import RawProcessorFuzzSI, RawSIDataRecord, RawSIInstructionRecord


def parse_processorfuzz_si(
    data: bytes, *, parser_profile_id: str = PARSER_PROFILE_ID,
) -> RawProcessorFuzzSI:
    """Parse the exact immutable bytes using the explicit confirmed-case profile.

    ASCII/LF only, mandatory final LF, no comments/BOM/tabs/normalization.
    Exceptions never include source tokens, raw lines or a Pydantic input dump.
    """

    if parser_profile_id != PARSER_PROFILE_ID:
        raise UnsupportedSIProfileError("unsupported SI parser profile")
    if type(data) is not bytes:
        raise ProcessorFuzzSIParseError("snapshot: immutable bytes required")
    digest = sha256(data).hexdigest()
    if any(byte != 10 and not 32 <= byte <= 126 for byte in data):
        raise ProcessorFuzzSIParseError("snapshot: only strict ASCII/LF text is supported")
    if not data.endswith(b"\n"):
        raise ProcessorFuzzSIParseError("snapshot: final LF required")
    lines = data.decode("ascii").split("\n")[:-1]
    if len(lines) < 5 or lines[0] != "p-m" or lines[1] != "":
        raise ProcessorFuzzSIParseError("header: expected profile token and blank second line")
    if lines.count("data:") != 1:
        raise ProcessorFuzzSIParseError("data: exactly one section delimiter required")
    boundary = lines.index("data:")
    instructions: list[RawSIInstructionRecord] = []
    records: list[RawSIDataRecord] = []
    for position, line in enumerate(lines[2:boundary], 3):
        try:
            label, mnemonic, operands, trailing = instruction_fields(line)
            instructions.append(RawSIInstructionRecord(
                source_line_number=position, instruction_ordinal=len(instructions),
                label=label, mnemonic=mnemonic, operand_tokens=operands,
                trailing_token=trailing, raw_line=line,
            ))
        except (ValidationError, ProcessorFuzzSIParseError):
            raise ProcessorFuzzSIParseError(f"line {position}: invalid instruction record") from None
    for position, line in enumerate(lines[boundary + 1:], boundary + 2):
        try:
            records.append(RawSIDataRecord(
                source_line_number=position, data_ordinal=len(records), hex_token=line,
            ))
        except ValidationError:
            raise ProcessorFuzzSIParseError(f"line {position}: invalid data record") from None
    try:
        return RawProcessorFuzzSI(
            parser_profile_id=PARSER_PROFILE_ID, snapshot_sha256=digest, byte_length=len(data),
            header="p-m", instructions=instructions, data_records=records,
        )
    except ValidationError:
        raise ProcessorFuzzSIParseError("snapshot: invalid layout, ordering or repeated labels") from None
