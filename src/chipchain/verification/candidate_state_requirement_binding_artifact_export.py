"""Deterministic presentation of B2-B source-relevance bindings only."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from chipchain.verification.candidate_state_observation_models import (
    CandidateEffectiveMemoryTypeObservation,
    CandidateExecutionContextObservation,
)
from chipchain.verification.candidate_state_requirement_binding import (
    CandidateStateRequirementBindingMaterialization,
)


_TEXT_FILENAMES = (
    "state_requirement_bindings.json",
    "state_requirement_bindings_summary.md",
    "state_requirement_bindings.dot",
)


@dataclass(frozen=True)
class CandidateStateRequirementBindingArtifactBundleResult:
    """Exact deterministic files emitted by the B2-B presentation layer."""

    files: tuple[str, ...]


def _detached(
    value: CandidateStateRequirementBindingMaterialization,
) -> CandidateStateRequirementBindingMaterialization:
    return CandidateStateRequirementBindingMaterialization.model_validate(
        value.model_dump(mode="json")
    )


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _observation_catalog(
    source: CandidateStateRequirementBindingMaterialization,
) -> dict[
    str,
    CandidateEffectiveMemoryTypeObservation
    | CandidateExecutionContextObservation,
]:
    return {
        observation.id: observation
        for materialization in (
            source.source_state_observation_materialization_snapshots
        )
        for observation in [
            *materialization.effective_memory_type_observations,
            *materialization.execution_context_observations,
        ]
    }


def render_candidate_state_requirement_binding_projection_json(
    materialization: CandidateStateRequirementBindingMaterialization,
) -> str:
    """Render only the deterministic B2-B relevance projection."""

    return _json(_detached(materialization).projection.model_dump(mode="json"))


def render_candidate_state_requirement_binding_summary_markdown(
    materialization: CandidateStateRequirementBindingMaterialization,
) -> str:
    """Render exact source relevance without value or satisfaction evaluation."""

    source = _detached(materialization)
    projection = source.projection
    observations = _observation_catalog(source)
    lines = [
        "# Candidate State Requirement Bindings",
        "",
        "Source relevance only; requirement satisfaction has not been evaluated.",
        "",
        "Program-location state association does not establish runtime execution or a memory access by that instruction.",
        "Value equality is not evaluated by this binding layer.",
        "Binding gaps record absence of relevant acquired observations, not requirement failure.",
        "",
        f"- Binding materialization ID: `{source.id}`",
        f"- Binding projection ID: `{projection.id}`",
        f"- Requirement materialization ID: `{projection.source_requirement_materialization_id}`",
        f"- Requirement projection ID: `{projection.source_requirement_projection_id}`",
        f"- State source count: {len(projection.source_state_materialization_ids)}",
        f"- Binding count: {len(projection.observation_requirement_bindings)}",
        f"- Acquisition gap count: {len(projection.acquisition_gaps)}",
        f"- Out-of-scope requirement count: {len(projection.out_of_scope_requirement_ids)}",
        "",
    ]
    lines.extend(f"- {value}" for value in projection.diagnostic_codes)
    lines.append("")
    for index, binding in enumerate(
        projection.observation_requirement_bindings, 1
    ):
        observation = observations[binding.source_state_observation_id]
        lines.extend(
            [
                f"## Source-Relevance Binding {index}",
                "",
                f"- Binding ID: `{binding.id}`",
                f"- Requirement ID: `{binding.source_requirement_id}`",
                f"- Requirement kind: `{binding.source_requirement_kind.value}`",
                f"- Case candidate ID: `{binding.source_case_candidate_id}`",
                f"- State materialization ID: `{binding.source_state_materialization_id}`",
                f"- State manifest ID: `{binding.source_state_manifest_id}`",
                f"- Observation ID: `{binding.source_state_observation_id}`",
                f"- Observation family: `{binding.source_observation_family.value}`",
                f"- Source-associated program location: `{observation.instruction_address.value}`",
                "- Matched subject position candidate IDs:",
                *(
                    f"  - `{value}`"
                    for value in binding.matched_subject_position_candidate_ids
                ),
                "- Matched subject fused fact node IDs:",
                *(
                    f"  - `{value}`"
                    for value in binding.matched_subject_fused_fact_node_ids
                ),
            ]
        )
        if isinstance(observation, CandidateEffectiveMemoryTypeObservation):
            lines.extend(
                [
                    f"- Source observation access address: `{observation.access_address.value}`",
                    f"- Source observation address kind: `{observation.access_address_kind}`",
                    f"- Source observation memory type: `{observation.observed_effective_memory_type_id}`",
                ]
            )
        else:
            lines.append(
                "- Source observation execution context IDs: "
                + ", ".join(
                    f"`{value}`"
                    for value in observation.observed_execution_context_ids
                )
            )
        lines.append("")
    for item in projection.acquisition_gaps:
        lines.append(
            f"- Acquisition gap `{item.id}`: requirement "
            f"`{item.source_requirement_id}` / `{item.reason.value}`"
        )
    if projection.acquisition_gaps:
        lines.append("")
    lines.extend(
        [
            "Typed Observation != Requirement Binding.",
            "",
            "Requirement Binding != Requirement Satisfaction.",
            "",
            "Evidence Relevance != Evidence Sufficiency.",
            "",
        ]
    )
    return "\n".join(lines)


def _dot_quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def render_candidate_state_requirement_binding_graph_dot(
    materialization: CandidateStateRequirementBindingMaterialization,
) -> str:
    """Render exactly one observation-to-requirement edge per binding."""

    projection = _detached(materialization).projection
    lines = [
        "digraph candidate_state_requirement_bindings {",
        "  rankdir=LR;",
        '  graph [label="Candidate State Requirement Bindings", labelloc="t"];',
        '  node [shape=box, fontname="sans-serif"];',
        '  edge [fontname="sans-serif"];',
        '  boundary [shape=note, label="Source relevance only; requirement satisfaction has not been evaluated."];',
        '  location_boundary [shape=note, label="Program-location state association does not establish runtime execution or a memory access by that instruction."];',
        '  value_boundary [shape=note, label="Value equality is not evaluated by this binding layer."];',
    ]
    observation_names: dict[str, str] = {}
    requirement_names: dict[str, str] = {}
    for binding in projection.observation_requirement_bindings:
        observation_name = observation_names.get(binding.source_state_observation_id)
        if observation_name is None:
            observation_name = f"observation_{len(observation_names) + 1}"
            observation_names[binding.source_state_observation_id] = observation_name
            label = (
                "Typed State Observation\n"
                + binding.source_observation_family.value
                + "\n"
                + binding.source_state_observation_id
            )
            lines.append(
                f"  {observation_name} [label={_dot_quote(label)}];"
            )
        requirement_name = requirement_names.get(binding.source_requirement_id)
        if requirement_name is None:
            requirement_name = f"requirement_{len(requirement_names) + 1}"
            requirement_names[binding.source_requirement_id] = requirement_name
            label = (
                "Verification Requirement\n"
                + binding.source_requirement_kind.value
                + "\n"
                + binding.source_requirement_id
            )
            lines.append(
                f"  {requirement_name} [label={_dot_quote(label)}];"
            )
        lines.append(
            f'  {observation_name} -> {requirement_name} [label="exact program-location source relevance"];'
        )
    lines.extend(["}", ""])
    return "\n".join(lines)


def export_candidate_state_requirement_binding_artifact_bundle(
    *,
    materialization: CandidateStateRequirementBindingMaterialization,
    output_directory: Path,
) -> CandidateStateRequirementBindingArtifactBundleResult:
    """Write four deterministic B2-B presentation files without evaluation."""

    source = _detached(materialization)
    outputs = {
        "state_requirement_bindings.json": (
            render_candidate_state_requirement_binding_projection_json(source)
        ),
        "state_requirement_bindings_summary.md": (
            render_candidate_state_requirement_binding_summary_markdown(source)
        ),
        "state_requirement_bindings.dot": (
            render_candidate_state_requirement_binding_graph_dot(source)
        ),
    }
    manifest = {
        "architecture": source.projection.architecture.value,
        "artifact_id": source.projection.artifact_id,
        "artifact_sha256": source.projection.artifact_sha256,
        "binding_materialization_id": source.id,
        "binding_projection_id": source.projection.id,
        "files": {
            name: {
                "byte_size": len(outputs[name].encode("utf-8")),
                "sha256": _sha256(outputs[name]),
            }
            for name in _TEXT_FILENAMES
        },
        "instruction_set": source.projection.instruction_set,
        "source_requirement_materialization_id": (
            source.source_requirement_materialization_id
        ),
        "source_state_materialization_ids": (
            source.projection.source_state_materialization_ids
        ),
    }
    outputs["manifest.json"] = _json(manifest)
    output_directory.mkdir(parents=True, exist_ok=True)
    for filename, content in outputs.items():
        (output_directory / filename).write_text(content, encoding="utf-8")
    return CandidateStateRequirementBindingArtifactBundleResult(
        files=(*_TEXT_FILENAMES, "manifest.json")
    )


__all__ = [
    "CandidateStateRequirementBindingArtifactBundleResult",
    "render_candidate_state_requirement_binding_projection_json",
    "render_candidate_state_requirement_binding_summary_markdown",
    "render_candidate_state_requirement_binding_graph_dot",
    "export_candidate_state_requirement_binding_artifact_bundle",
]
