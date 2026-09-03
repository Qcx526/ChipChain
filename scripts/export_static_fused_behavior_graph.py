"""Export a provenance-bound fused static behavior graph for inspection."""

from __future__ import annotations

import argparse
from pathlib import Path

from chipchain.analysis import (
    AngrAArch64StaticProgramStructureExtractor,
    AngrAArch64StaticSemanticDecoder,
    ProgramArtifact,
    export_static_fused_behavior_artifact_bundle,
    fuse_static_semantic_and_program_structure,
    project_static_semantic_inventory,
)
from chipchain.models import Architecture


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Export a deterministic C2-C fused static behavior graph from "
            "the two frozen AArch64 source analyzers."
        )
    )
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--artifact-id", required=True)
    parser.add_argument("--fixture-id")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--no-svg",
        action="store_true",
        help="Do not attempt optional local Graphviz SVG rendering.",
    )
    return parser


def main() -> int:
    """Run independent frozen sources, pure fusion and presentation export."""

    arguments = _parser().parse_args()
    artifact = ProgramArtifact(
        id=arguments.artifact_id,
        architecture=Architecture.ARM,
        artifact_type="elf",
        path=str(arguments.binary),
        fixture_identifier=arguments.fixture_id,
    )
    semantic = AngrAArch64StaticSemanticDecoder().decode(artifact)
    semantic_graph = project_static_semantic_inventory(semantic)
    structure = AngrAArch64StaticProgramStructureExtractor().extract(artifact)
    fused = fuse_static_semantic_and_program_structure(
        semantic_graph, structure
    )
    result = export_static_fused_behavior_artifact_bundle(
        materialization=fused,
        output_directory=arguments.output_dir,
        include_svg=not arguments.no_svg,
    )
    for filename in result.files:
        print(filename)
    if result.svg_files:
        for filename in result.svg_files:
            print(filename)
    else:
        print("Optional SVG: not generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
