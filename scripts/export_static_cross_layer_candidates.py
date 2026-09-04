"""Export deterministic static cross-layer reference candidates."""

from __future__ import annotations

import argparse
from pathlib import Path

from chipchain.analysis import (
    AngrAArch64StaticProgramStructureExtractor,
    AngrAArch64StaticSemanticDecoder,
    ProgramArtifact,
    StaticDocumentedErratumHardwareReference,
    StaticHardwareReferenceCatalog,
    StaticOwnedSyntheticHardwareReference,
    StaticTriggerPattern,
    StaticTriggerPatternCatalog,
    bind_static_trigger_candidates_to_hardware_references,
    export_static_cross_layer_candidate_artifact_bundle,
    fuse_static_semantic_and_program_structure,
    project_static_semantic_inventory,
    project_static_trigger_candidates,
    translate_documented_erratum_to_aarch64_static_trigger_pattern,
)
from chipchain.hardware_trigger.documented_erratum_models import (
    DocumentedHardwareErratumContract,
)
from chipchain.models import Architecture


ROOT = Path(__file__).resolve().parents[1]
OWNED_BINARY = (
    ROOT / "tests/fixtures/phase10d/aarch64_static_fused_behavior_v1/"
    "aarch64_static_fused_behavior_v1.elf"
)
OWNED_PATTERN = (
    ROOT / "tests/fixtures/phase10d/static_trigger_pattern_v1/"
    "owned_synthetic_static_trigger_pattern_v1.json"
)
PUBLIC_A77_BINARY = (
    ROOT / "tests/fixtures/phase10d/a_profile_static_semantic_a64/"
    "a_profile_static_semantic_a64.elf"
)
DOCUMENTED_ERRATUM = (
    ROOT / "data/evaluation/"
    "cve_2023_34320_documented_erratum_1508412_v1.json"
)
GENERATED_PUBLIC_PATTERN = (
    ROOT / "data/evaluation/"
    "cve_2023_34320_generic_aarch64_static_trigger_pattern_v1.json"
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export source-backed static cross-layer reference candidates."
    )
    parser.add_argument("--mode", choices=("owned", "public-a77"), required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--no-svg",
        action="store_true",
        help="Do not attempt optional local Graphviz SVG rendering.",
    )
    return parser


def _analyze(binary: Path, artifact_id: str, fixture_id: str):
    artifact = ProgramArtifact(
        id=artifact_id,
        architecture=Architecture.ARM,
        artifact_type="elf",
        path=str(binary),
        fixture_identifier=fixture_id,
        metadata={"owned": True, "synthetic": True, "fixture": True},
    )
    semantic = AngrAArch64StaticSemanticDecoder().decode(artifact)
    semantic_graph = project_static_semantic_inventory(semantic)
    structure = AngrAArch64StaticProgramStructureExtractor().extract(artifact)
    return fuse_static_semantic_and_program_structure(semantic_graph, structure)


def build_owned_static_cross_layer_materialization():
    """Build the owned, synthetic, benign source-reference example."""

    fused = _analyze(
        OWNED_BINARY,
        "owned-synthetic-aarch64-static-fused-behavior-v1",
        "phase10d-aarch64-static-fused-behavior-v1",
    )
    pattern = StaticTriggerPattern.model_validate_json(OWNED_PATTERN.read_bytes())
    candidates = project_static_trigger_candidates(
        fused, StaticTriggerPatternCatalog.create(patterns=[pattern])
    )
    references = [
        StaticOwnedSyntheticHardwareReference.create(
            reference_id=reference_id,
            architecture=Architecture.ARM,
            title=reference_id.replace("-", " "),
            source_reference_ids=[
                "owned-synthetic-static-hardware-reference-design-v1"
            ],
        )
        for reference_id in pattern.hardware_reference_ids
    ]
    return bind_static_trigger_candidates_to_hardware_references(
        candidates,
        StaticHardwareReferenceCatalog.create(references=references),
    )


def _serialize_pattern(pattern: StaticTriggerPattern) -> str:
    return pattern.model_dump_json(indent=2, ensure_ascii=False) + "\n"


def build_public_a77_static_cross_layer_materialization():
    """Build the owned A77 fixture result against documented source metadata."""

    erratum = DocumentedHardwareErratumContract.model_validate_json(
        DOCUMENTED_ERRATUM.read_bytes()
    )
    pattern = translate_documented_erratum_to_aarch64_static_trigger_pattern(
        erratum
    )
    if GENERATED_PUBLIC_PATTERN.read_text(encoding="utf-8") != _serialize_pattern(
        pattern
    ):
        raise ValueError("generated public static trigger pattern changed")
    fused = _analyze(
        PUBLIC_A77_BINARY,
        "owned-synthetic-a77-static-program-structure-v1",
        "phase10d-a-profile-static-semantic-a64-v1",
    )
    candidates = project_static_trigger_candidates(
        fused, StaticTriggerPatternCatalog.create(patterns=[pattern])
    )
    reference = StaticDocumentedErratumHardwareReference.create(
        reference_id=erratum.id,
        architecture=Architecture.ARM,
        source_documented_erratum_snapshot=erratum,
    )
    return bind_static_trigger_candidates_to_hardware_references(
        candidates,
        StaticHardwareReferenceCatalog.create(references=[reference]),
    )


def main() -> int:
    """Run frozen static orchestration and export reference candidates."""

    arguments = _parser().parse_args()
    materialization = (
        build_owned_static_cross_layer_materialization()
        if arguments.mode == "owned"
        else build_public_a77_static_cross_layer_materialization()
    )
    result = export_static_cross_layer_candidate_artifact_bundle(
        materialization=materialization,
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
