"""Explicit local SI syntax profile and partial, non-verification projection."""

from chipchain.adapters.processorfuzz._syntax import PARSER_PROFILE_ID
from chipchain.adapters.processorfuzz.errors import (
    ProcessorFuzzSIError, ProcessorFuzzSIIntegrityError, ProcessorFuzzSIParseError, UnsupportedSIProfileError,
)
from chipchain.adapters.processorfuzz.mapper import map_processorfuzz_si
from chipchain.adapters.processorfuzz.models import RawProcessorFuzzSI, RawSIDataRecord, RawSIInstructionRecord
from chipchain.adapters.processorfuzz.parser import parse_processorfuzz_si

__all__ = [
    "PARSER_PROFILE_ID", "ProcessorFuzzSIError", "ProcessorFuzzSIIntegrityError",
    "ProcessorFuzzSIParseError", "UnsupportedSIProfileError", "RawProcessorFuzzSI",
    "RawSIInstructionRecord", "RawSIDataRecord", "parse_processorfuzz_si", "map_processorfuzz_si",
]
