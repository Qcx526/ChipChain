"""Offline maintenance entry point for the generated public-CVE snapshot."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
import sys

from chipchain.corpus import (
    build_public_cve_corpus,
    load_public_cve_source,
    serialize_public_cve_corpus,
    write_public_cve_corpus,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = (
    ROOT / "data/public_cve/source/arm_cross_layer_seed_v1.source.json"
)
DEFAULT_OUTPUT = ROOT / "data/public_cve/arm_cross_layer_seed_v1.json"


def build_parser() -> argparse.ArgumentParser:
    """Create the narrow offline maintenance parser."""

    parser = argparse.ArgumentParser(
        description="Build the public CVE corpus from its authoritative source."
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--check",
        action="store_true",
        help="Compare deterministic output with the committed snapshot.",
    )
    action.add_argument(
        "--write",
        action="store_true",
        help="Regenerate the committed snapshot deterministically.",
    )
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run a local check or write without network/provider initialization."""

    args = build_parser().parse_args(argv)
    corpus = build_public_cve_corpus(load_public_cve_source(args.source))
    if args.check:
        expected = serialize_public_cve_corpus(corpus)
        try:
            actual = args.output.read_text(encoding="utf-8")
        except OSError:
            return 1
        return 0 if actual == expected else 1
    write_public_cve_corpus(corpus, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
