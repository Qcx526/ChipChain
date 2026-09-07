"""Deterministic presentation of typed sources without downstream bindings."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from chipchain.verification.candidate_state_observation_models import CandidateStateObservationMaterialization


_BOUNDARY = "Typed state observations only; no verification requirement has been evaluated."


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _detached(value: CandidateStateObservationMaterialization) -> CandidateStateObservationMaterialization:
    return CandidateStateObservationMaterialization.model_validate(value.model_dump(mode="json"))


def render_candidate_state_observations_json(value: CandidateStateObservationMaterialization) -> str:
    """Render the entire authoritative normalized source representation."""
    return _json(_detached(value).model_dump(mode="json"))


def render_candidate_state_observations_summary(value: CandidateStateObservationMaterialization) -> str:
    """Display explicit source values and the limits of their provenance."""
    source = _detached(value)
    manifest = source.source_manifest_snapshot
    lines = [
        "# Typed Candidate State Observations", "", _BOUNDARY, "",
        "State-source instruction addresses do not assert runtime execution.",
        "For effective-memory-type records, instruction/address association does not establish that the instruction performed that memory access.",
        "Declared source artifact hash is not independent raw-file verification.",
        "audited_translation_resolution is a producer-profile-declared deterministic normalization basis, not independent ChipChain translation verification.",
        "The typed materialization is authoritative; producer profiles are provenance, not trust scores.",
        "Owned fixtures are synthetic, not real runtime measurements.", "",
        f"- Materialization ID: `{source.id}`",
        f"- Source manifest ID: `{manifest.id}`",
        f"- Architecture / instruction set: `{manifest.architecture.value}` / `{manifest.instruction_set}`",
        f"- Artifact ID / SHA-256: `{manifest.artifact_id}` / `{manifest.artifact_sha256}`",
        f"- Source kind: `{manifest.source_kind}`",
        f"- Producer: `{manifest.producer_profile_id}` / `{manifest.producer_profile_version}`",
        f"- Normalization profile: `{manifest.normalization_profile_id}`",
        f"- Declared source artifact: `{manifest.source_artifact_id}` / `{manifest.source_artifact_sha256}`",
        f"- Memory observations: {len(source.effective_memory_type_observations)}",
        f"- Context observations: {len(source.execution_context_observations)}", "",
    ]
    for observation in [*source.effective_memory_type_observations, *source.execution_context_observations]:
        lines.extend([f"## Source record `{observation.source_record_locator}`", "", "```json", _json(observation.model_dump(mode="json")).rstrip(), "```", ""])
    return "\n".join(lines)


def render_candidate_state_observations_dot(value: CandidateStateObservationMaterialization) -> str:
    """Show only source-manifest to typed-observation provenance edges."""
    source = _detached(value)
    quote = lambda text: json.dumps(text, ensure_ascii=False)
    lines = ["digraph candidate_state_observations {", "  rankdir=LR;",
             f"  graph [label={quote(_BOUNDARY)}, labelloc=\"t\"];",
             f"  boundary [shape=note, label={quote('Program-location association does not establish runtime execution or a memory access by that instruction.')}];",
             f"  source [shape=box, label={quote('Source Manifest' + chr(10) + source.source_manifest_snapshot.id)}];"]
    for index, observation in enumerate([*source.effective_memory_type_observations, *source.execution_context_observations]):
        label = f"Typed Observation\n{observation.id}\n{observation.source_record_locator}\nsource instruction: {observation.instruction_address.value}"
        lines.extend([f"  observation_{index} [shape=box, label={quote(label)}];",
                      f'  source -> observation_{index} [label="source record provenance"];'])
    return "\n".join([*lines, "}", ""])


def export_candidate_state_observations(
    *, materialization: CandidateStateObservationMaterialization, output_directory: Path,
) -> tuple[str, ...]:
    """Write four deterministic text artifacts; never invoke a graph renderer."""
    source = _detached(materialization)
    outputs = {
        "state_observations.json": render_candidate_state_observations_json(source),
        "state_observations_summary.md": render_candidate_state_observations_summary(source),
        "state_observations.dot": render_candidate_state_observations_dot(source),
    }
    manifest = source.source_manifest_snapshot
    outputs["manifest.json"] = _json({
        "architecture": manifest.architecture.value,
        "artifact_id": manifest.artifact_id,
        "artifact_sha256": manifest.artifact_sha256,
        "instruction_set": manifest.instruction_set,
        "source_materialization_id": source.id,
        "source_manifest_id": manifest.id,
        "files": {name: {"sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                         "byte_size": len(text.encode("utf-8"))} for name, text in outputs.items()},
    })
    output_directory.mkdir(parents=True, exist_ok=True)
    for name, text in outputs.items():
        (output_directory / name).write_bytes(text.encode("utf-8"))
    return tuple(sorted(outputs))


__all__ = ["render_candidate_state_observations_json", "render_candidate_state_observations_summary",
           "render_candidate_state_observations_dot", "export_candidate_state_observations"]
