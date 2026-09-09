"""Command-line shell for the ChipChain V2 foundation."""

import argparse
from collections.abc import Sequence

from chipchain import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build the help/version shell; research commands are not implemented."""

    parser = argparse.ArgumentParser(
        prog="chipchain",
        description=(
            "ChipChain V2: RISC-V-first cross-layer trigger reachability. "
            "V2-R0 provides core contracts only; analysis commands are not implemented."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI shell and return a process exit code."""

    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
