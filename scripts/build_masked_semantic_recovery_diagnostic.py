"""Offline builder for the masked semantic-recovery diagnostic artifact."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
import sys

from chipchain.evaluation.semantic_recovery import (
    build_masked_semantic_recovery_diagnostic_from_files,
    serialize_masked_semantic_recovery_diagnostic,
    write_masked_semantic_recovery_diagnostic,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARCHIVE = (
    ROOT
    / "data/evaluation/runs/"
    "phase10d_step8b1d_public_deepseek_20260831_one_shot.json"
)
DEFAULT_SOURCE = (
    ROOT / "data/public_cve/source/arm_cross_layer_seed_v1.source.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "data/evaluation/"
    "public_documented_arm_secondary_masked_semantic_recovery_v1.json"
)


def build_parser() -> argparse.ArgumentParser:
    """Create the narrow, local-only diagnostic builder parser."""

    parser = argparse.ArgumentParser(
        description="Build the retrospective MASKED semantic-recovery diagnostic."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare deterministic bytes with the committed artifact.",
    )
    parser.add_argument("--source-archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--public-source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Build or check the artifact without provider, network, or QEMU access."""

    args = build_parser().parse_args(argv)
    artifact = build_masked_semantic_recovery_diagnostic_from_files(
        source_archive_path=args.source_archive,
        public_source_path=args.public_source,
    )
    expected = serialize_masked_semantic_recovery_diagnostic(artifact)
    if args.check:
        try:
            actual = args.output.read_bytes()
        except OSError:
            return 1
        return 0 if actual == expected else 1
    write_masked_semantic_recovery_diagnostic(artifact, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
