"""Confirmed ISA-side description/commit/context snapshot adapter."""

from chipchain.core import Architecture
from chipchain.evidence import ParsedCaseArtifact, TraceSourceSide
from chipchain.adapters.hardware_case._common import parse_snapshot


def parse_isa_log(data: bytes, *, architecture: Architecture, expected_sha256: str | None = None) -> ParsedCaseArtifact:
    """Preserve distinct record kinds; never infer post-state or ground truth."""

    return parse_snapshot(data, profile="confirmed_isa_log_v1", side=TraceSourceSide.ISA_SIDE, architecture=architecture, expected_sha256=expected_sha256)
