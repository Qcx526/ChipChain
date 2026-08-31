"""Offline builder for the first A-profile static extraction plan."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
import sys

from chipchain.hardware_trigger.a_profile_static_semantic import (
    build_a_profile_static_semantic_extraction_plan,
    serialize_a_profile_static_semantic_extraction_plan,
    write_a_profile_static_semantic_extraction_plan,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_a_profile_semantic_trigger_pattern_v1.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_a_profile_static_semantic_extraction_plan_v1.json"
)
EXPECTED_SOURCE_PATTERN_ID = (
    "a-profile-semantic-trigger-pattern:"
    "25599b751ead0dc36a39787000fad60aa0cea6485913cdf52b248e037ec21d77"
)
EXPECTED_SOURCE_PATTERN_SHA256 = (
    "6a56e75078475fd5133524c8aef28233a431283b151960ea9389d2430ce2ceb0"
)


def build_parser() -> argparse.ArgumentParser:
    """Create the deterministic offline maintenance parser."""

    parser = argparse.ArgumentParser(
        description="Build the CVE-2023-34320 A-profile static extraction plan."
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--check",
        action="store_true",
        help="Compare deterministic output with the committed plan.",
    )
    action.add_argument(
        "--write",
        action="store_true",
        help="Regenerate the committed plan deterministically.",
    )
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Translate the frozen 2B1 pattern without opening an ELF."""

    args = build_parser().parse_args(argv)
    plan = build_a_profile_static_semantic_extraction_plan(
        semantic_pattern_bytes=args.source.read_bytes(),
        expected_source_pattern_id=EXPECTED_SOURCE_PATTERN_ID,
        expected_source_pattern_sha256=EXPECTED_SOURCE_PATTERN_SHA256,
    )
    if args.check:
        expected = serialize_a_profile_static_semantic_extraction_plan(plan)
        try:
            actual = args.output.read_text(encoding="utf-8")
        except OSError:
            return 1
        return 0 if actual == expected else 1
    write_a_profile_static_semantic_extraction_plan(plan, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
