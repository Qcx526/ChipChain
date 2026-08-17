"""Export versionable ChipChain domain contracts as JSON Schema."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from chipchain.models import AttackChain, VulnerabilitySample


def build_parser() -> argparse.ArgumentParser:
    """Create the schema export argument parser."""

    parser = argparse.ArgumentParser(
        description="Export ChipChain VulnerabilitySample and AttackChain schemas."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/schema"),
        help="Output directory (default: artifacts/schema).",
    )
    return parser


def write_schema(path: Path, schema: dict[str, object]) -> None:
    """Write one JSON Schema using deterministic, readable formatting."""

    path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    """Export both public core schemas and return a process exit code."""

    args = build_parser().parse_args()
    output: Path = args.output
    output.mkdir(parents=True, exist_ok=True)
    write_schema(
        output / "vulnerability_sample.schema.json",
        VulnerabilitySample.model_json_schema(),
    )
    write_schema(
        output / "attack_chain.schema.json",
        AttackChain.model_json_schema(),
    )
    print(f"Exported schemas to {output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
