"""Offline maintenance entry point for the public SECONDARY cohort."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
import sys

from chipchain.corpus import load_public_cve_corpus, load_public_cve_source
from chipchain.evaluation.public_secondary import (
    load_public_secondary_selection,
    materialize_public_secondary_cohort,
    serialize_public_secondary_cohort,
    write_public_secondary_cohort,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = (
    ROOT / "data/public_cve/source/arm_cross_layer_seed_v1.source.json"
)
DEFAULT_CORPUS = ROOT / "data/public_cve/arm_cross_layer_seed_v1.json"
DEFAULT_SELECTION = (
    ROOT / "data/public_cve/evaluation/arm_secondary_v1.json"
)
DEFAULT_OUTPUT = (
    ROOT / "data/evaluation/public_documented_arm_secondary_v1.json"
)


def build_parser() -> argparse.ArgumentParser:
    """Create the narrow offline cohort-maintenance parser."""

    parser = argparse.ArgumentParser(
        description="Build the public-documented ARM SECONDARY cohort."
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--check",
        action="store_true",
        help="Compare deterministic output with the committed cohort.",
    )
    action.add_argument(
        "--write",
        action="store_true",
        help="Regenerate the committed cohort deterministically.",
    )
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--selection", type=Path, default=DEFAULT_SELECTION)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run local materialization without provider, QEMU, or network access."""

    args = build_parser().parse_args(argv)
    cohort = materialize_public_secondary_cohort(
        source=load_public_cve_source(args.source),
        corpus=load_public_cve_corpus(args.corpus),
        selection=load_public_secondary_selection(args.selection),
    )
    if args.check:
        expected = serialize_public_secondary_cohort(cohort)
        try:
            actual = args.output.read_text(encoding="utf-8")
        except OSError:
            return 1
        return 0 if actual == expected else 1
    write_public_secondary_cohort(cohort, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
