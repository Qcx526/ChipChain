"""Closed descriptive vocabulary; these levels do not imply verification."""

from enum import StrEnum


class EvidenceLevel(StrEnum):
    BYTE_VERIFIED = "BYTE_VERIFIED"
    FORMAT_OBSERVED = "FORMAT_OBSERVED"
    PRODUCER_DECLARED = "PRODUCER_DECLARED"
    CROSS_ARTIFACT_CORRELATED = "CROSS_ARTIFACT_CORRELATED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class TraceSourceSide(StrEnum):
    ISA_SIDE = "ISA_SIDE"
    RTL_SIDE = "RTL_SIDE"


class ComparableField(StrEnum):
    MSTATUS = "mstatus"
    FRM = "frm"
    FFLAGS = "fflags"
    MCAUSE = "mcause"
    SCAUSE = "scause"
    MEDELEG = "medeleg"
    MCOUNTEREN = "mcounteren"
    SCOUNTEREN = "scounteren"


class ComparisonOutcome(StrEnum):
    EQUAL = "EQUAL"
    DIFFERENT = "DIFFERENT"
    NOT_COMPARABLE = "NOT_COMPARABLE"
    MISSING_LEFT = "MISSING_LEFT"
    MISSING_RIGHT = "MISSING_RIGHT"
