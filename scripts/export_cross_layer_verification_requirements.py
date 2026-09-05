"""Export deterministic objective verification requirements from frozen sources."""

from __future__ import annotations

import argparse
from pathlib import Path
import runpy

from chipchain.verification import (
    export_cross_layer_verification_requirement_artifact_bundle,
    project_cross_layer_verification_requirements,
)

ROOT = Path(__file__).resolve().parents[1]
_SOURCE_RUNNER = runpy.run_path(
    str(ROOT / "scripts/export_static_cross_layer_candidates.py"),
    run_name="phase10d_static_cross_layer_source_runner",
)
build_owned_static_cross_layer_materialization = _SOURCE_RUNNER[
    "build_owned_static_cross_layer_materialization"
]
build_public_a77_static_cross_layer_materialization = _SOURCE_RUNNER[
    "build_public_a77_static_cross_layer_materialization"
]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export source-bound objective evidence requirements only."
    )
    parser.add_argument("--mode", choices=("owned", "public-a77"), required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--no-svg", action="store_true")
    return parser


def build_owned_verification_requirement_materialization():
    """Project the frozen owned static cross-layer example."""

    return project_cross_layer_verification_requirements(
        build_owned_static_cross_layer_materialization()
    )


def build_public_a77_verification_requirement_materialization():
    """Project the frozen public A77 zero-candidate example."""

    return project_cross_layer_verification_requirements(
        build_public_a77_static_cross_layer_materialization()
    )


def main() -> int:
    arguments = _parser().parse_args()
    materialization = (
        build_owned_verification_requirement_materialization()
        if arguments.mode == "owned"
        else build_public_a77_verification_requirement_materialization()
    )
    result = export_cross_layer_verification_requirement_artifact_bundle(
        materialization=materialization,
        output_directory=arguments.output_dir,
        include_svg=not arguments.no_svg,
    )
    for filename in result.files:
        print(filename)
    if not result.svg_files:
        print("Optional SVG: not generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
