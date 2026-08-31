"""Offline builder for the first A-profile semantic trigger pattern."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
import sys

from chipchain.hardware_trigger.a_profile_semantic import (
    build_a_profile_semantic_trigger_pattern,
    serialize_a_profile_semantic_trigger_pattern,
    write_a_profile_semantic_trigger_pattern,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_documented_erratum_1508412_v1.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_a_profile_semantic_trigger_pattern_v1.json"
)


def build_parser() -> argparse.ArgumentParser:
    """Create the deterministic offline maintenance parser."""

    parser = argparse.ArgumentParser(
        description="Build the CVE-2023-34320 A-profile semantic pattern."
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--check",
        action="store_true",
        help="Compare deterministic output with the committed artifact.",
    )
    action.add_argument(
        "--write",
        action="store_true",
        help="Regenerate the committed artifact deterministically.",
    )
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Translate the frozen 2B0 artifact without network or runtime access."""

    args = build_parser().parse_args(argv)
    pattern = build_a_profile_semantic_trigger_pattern(
        documented_erratum_bytes=args.source.read_bytes()
    )
    if args.check:
        expected = serialize_a_profile_semantic_trigger_pattern(pattern)
        try:
            actual = args.output.read_text(encoding="utf-8")
        except OSError:
            return 1
        return 0 if actual == expected else 1
    write_a_profile_semantic_trigger_pattern(pattern, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
