"""Command-line interface for ChipChain."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from chipchain import __version__


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level argument parser."""

    parser = argparse.ArgumentParser(
        prog="chipchain",
        description=(
            "Evidence-guided detection and verification of cross-layer chip "
            "vulnerability chains."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the ChipChain CLI and return a process exit code."""

    parser = build_parser()
    parser.parse_args(argv)
    return 0
