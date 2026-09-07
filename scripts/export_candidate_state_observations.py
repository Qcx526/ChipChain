"""Export only the new owned synthetic typed-source fixture (no analysis run)."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from chipchain.verification.candidate_state_observation_models import (
    CandidateEffectiveMemoryTypeObservation, CandidateExecutionContextObservation,
    CandidateStateObservationMaterialization, CandidateStateObservationSourceManifest,
)
from chipchain.verification.candidate_state_observation_artifact_export import export_candidate_state_observations


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/phase10d/candidate_state_observation_v1/owned_state_source.json"


def build_owned_candidate_state_observations() -> CandidateStateObservationMaterialization:
    """Normalize explicit fixture records; hash and parse the same byte snapshot.

This fixture-only loader measures its available input bytes. Core source models
do not independently authenticate a producer's declared external artifact SHA.
"""
    snapshot = FIXTURE.read_bytes()
    source = json.loads(snapshot)
    manifest = CandidateStateObservationSourceManifest.create(
        **source["manifest"], source_artifact_sha256=hashlib.sha256(snapshot).hexdigest(),
    )
    common = {key: getattr(manifest, key) for key in ("architecture", "artifact_id", "artifact_sha256", "instruction_set")}
    common["source_manifest_id"] = manifest.id
    return CandidateStateObservationMaterialization.create(
        source_manifest_snapshot=manifest,
        effective_memory_type_observations=[CandidateEffectiveMemoryTypeObservation.create(**common, **record) for record in source["effective_memory_type_observations"]],
        execution_context_observations=[CandidateExecutionContextObservation.create(**common, **record) for record in source["execution_context_observations"]],
    )


def main() -> int:
    """Write the owned source bundle without collecting any measurements."""
    parser = argparse.ArgumentParser(description="Export owned synthetic typed state observations only.")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    for name in export_candidate_state_observations(materialization=build_owned_candidate_state_observations(), output_directory=args.output_dir):
        print(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
