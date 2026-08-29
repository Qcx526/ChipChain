"""Offline builder for versioned public-knowledge prompt readiness."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
import sys

from chipchain.corpus import load_public_cve_corpus
from chipchain.evaluation.public_knowledge_readiness import (
    materialize_public_knowledge_readiness,
    serialize_public_knowledge_readiness,
    write_public_knowledge_readiness,
)
from chipchain.evaluation.public_secondary import load_public_secondary_cohort


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "data/public_cve/arm_cross_layer_seed_v1.json"
DEFAULT_FROZEN_COHORT = (
    ROOT / "data/evaluation/public_documented_arm_secondary_v1.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "data/evaluation/public_documented_arm_secondary_knowledge_projection_v1.json"
)


def build_parser() -> argparse.ArgumentParser:
    """Create the narrow offline readiness-maintenance parser."""

    parser = argparse.ArgumentParser(
        description="Build public-knowledge projected prompt readiness."
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
        help="Regenerate the committed readiness artifact.",
    )
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument(
        "--frozen-cohort",
        type=Path,
        default=DEFAULT_FROZEN_COHORT,
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run local readiness construction without external execution."""

    args = build_parser().parse_args(argv)
    artifact = materialize_public_knowledge_readiness(
        frozen_cohort=load_public_secondary_cohort(args.frozen_cohort),
        corpus=load_public_cve_corpus(args.corpus),
    )
    if args.check:
        expected = serialize_public_knowledge_readiness(artifact)
        try:
            actual = args.output.read_text(encoding="utf-8")
        except OSError:
            return 1
        return 0 if actual == expected else 1
    write_public_knowledge_readiness(artifact, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
