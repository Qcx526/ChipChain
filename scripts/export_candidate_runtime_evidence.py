"""Export deterministic owned Phase 10D 2D4-B1 runtime evidence."""

from __future__ import annotations

import argparse
from pathlib import Path
import runpy

from chipchain.runtime import RuntimeTrace
from chipchain.verification.candidate_runtime_evidence_artifact_export import (
    export_candidate_runtime_evidence_artifact_bundle,
)
from chipchain.verification.candidate_runtime_evidence_binding import (
    bind_candidate_runtime_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
TRACE_PATH = (
    ROOT
    / "tests/fixtures/phase10d/candidate_runtime_evidence_v1/"
    "owned_diamond_runtime_trace.json"
)
_REQUIREMENT_RUNNER = runpy.run_path(
    str(ROOT / "scripts/export_cross_layer_verification_requirements.py"),
    run_name="phase10d_candidate_runtime_requirement_source_runner",
)


def build_owned_candidate_runtime_evidence_materialization():
    """Build B1 output from frozen 2D4-A and the owned trace fixture."""

    requirements = _REQUIREMENT_RUNNER[
        "build_owned_verification_requirement_materialization"
    ]()
    trace = RuntimeTrace.model_validate_json(TRACE_PATH.read_bytes())
    return bind_candidate_runtime_evidence(requirements, [trace])


def main() -> int:
    """Export the owned runtime evidence artifact bundle."""

    parser = argparse.ArgumentParser(
        description="Export source-bound runtime evidence observations only."
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--no-svg", action="store_true")
    arguments = parser.parse_args()
    result = export_candidate_runtime_evidence_artifact_bundle(
        materialization=build_owned_candidate_runtime_evidence_materialization(),
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
