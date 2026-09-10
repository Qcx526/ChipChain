"""Confirmed RocketTile/Verilator local print-profile snapshot adapter."""

from chipchain.core import Architecture
from chipchain.evidence import ParsedCaseArtifact, TraceSourceSide
from chipchain.adapters.hardware_case._common import parse_snapshot


def parse_rtl_log(data: bytes, *, architecture: Architecture, expected_sha256: str | None = None) -> ParsedCaseArtifact:
    """Parse NORMAL/EXCEPTION/DELAYED without interpreting COV as time."""

    return parse_snapshot(data, profile="confirmed_rocket_rtl_log_v1", side=TraceSourceSide.RTL_SIDE, architecture=architecture, expected_sha256=expected_sha256)
