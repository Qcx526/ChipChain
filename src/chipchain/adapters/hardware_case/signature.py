"""Confirmed fixed-size opaque signature snapshot adapter."""

from chipchain.core import Architecture
from chipchain.evidence import ParsedCaseArtifact, TraceSourceSide
from chipchain.adapters.hardware_case._common import parse_snapshot


def parse_signature(data: bytes, *, source_side: TraceSourceSide, architecture: Architecture, expected_sha256: str | None = None) -> ParsedCaseArtifact:
    """Parse 254 raw rows independently per side, without CSR/address mapping."""

    return parse_snapshot(data, profile="confirmed_signature_v1", side=source_side, architecture=architecture, expected_sha256=expected_sha256)
