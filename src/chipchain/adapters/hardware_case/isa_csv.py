"""Confirmed 17-column ISA CSV snapshot adapter, not a universal ISA parser."""

from chipchain.core import Architecture
from chipchain.evidence import ParsedCaseArtifact, TraceSourceSide
from chipchain.adapters.hardware_case._common import parse_snapshot


def parse_isa_csv(data: bytes, *, architecture: Architecture, expected_sha256: str | None = None) -> ParsedCaseArtifact:
    """Parse exact ASCII/CRLF bytes without fabricating missing mode/state."""

    return parse_snapshot(data, profile="confirmed_isa_csv_v1", side=TraceSourceSide.ISA_SIDE, architecture=architecture, expected_sha256=expected_sha256)
