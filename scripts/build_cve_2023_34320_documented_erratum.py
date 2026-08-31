"""Offline builder for the CVE-2023-34320 documented erratum contract."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
import sys

from chipchain.hardware_trigger.documented_erratum import (
    build_documented_hardware_erratum,
    load_documented_erratum_source,
    serialize_documented_hardware_erratum,
    write_documented_hardware_erratum,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = (
    ROOT
    / "data/public_cve/objective/"
    "cve_2023_34320_erratum_1508412.source.json"
)
DEFAULT_PUBLIC_SOURCE = (
    ROOT / "data/public_cve/source/arm_cross_layer_seed_v1.source.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_documented_erratum_1508412_v1.json"
)


def build_parser() -> argparse.ArgumentParser:
    """Create the narrow offline maintenance parser."""

    parser = argparse.ArgumentParser(
        description="Build the CVE-2023-34320 documented erratum contract."
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
    parser.add_argument(
        "--public-source", type=Path, default=DEFAULT_PUBLIC_SOURCE
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Materialize documented semantics without network or runtime access."""

    args = build_parser().parse_args(argv)
    contract = build_documented_hardware_erratum(
        load_documented_erratum_source(args.source),
        public_source_bytes=args.public_source.read_bytes(),
    )
    if args.check:
        expected = serialize_documented_hardware_erratum(contract)
        try:
            actual = args.output.read_text(encoding="utf-8")
        except OSError:
            return 1
        return 0 if actual == expected else 1
    write_documented_hardware_erratum(contract, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
