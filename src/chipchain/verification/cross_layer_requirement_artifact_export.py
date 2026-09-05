"""Pure deterministic presentation of cross-layer verification requirements."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from chipchain.analysis.static_analysis_artifact_export import (
    escape_dot_string,
    render_dot_to_svg_if_available,
)
from chipchain.verification.cross_layer_requirements import (
    StaticCrossLayerVerificationRequirementMaterialization,
)


_TEXT_FILENAMES = (
    "verification_requirements.json",
    "verification_requirements_summary.md",
    "verification_requirements.dot",
)


@dataclass(frozen=True)
class CrossLayerVerificationRequirementArtifactBundleResult:
    files: tuple[str, ...]
    svg_files: tuple[str, ...]


def _detached(value):
    return StaticCrossLayerVerificationRequirementMaterialization.model_validate(
        value.model_dump(mode="json")
    )


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def render_cross_layer_verification_requirement_projection_json(materialization) -> str:
    """Render only the deterministic requirement projection."""

    return _json(_detached(materialization).projection.model_dump(mode="json"))


def render_cross_layer_verification_requirement_summary_markdown(materialization) -> str:
    """Render requirement subjects without implying evidence or an outcome."""

    source = _detached(materialization)
    projection = source.projection
    lines = [
        "# Cross-Layer Verification Requirements",
        "",
        "Requirements only; no evidence has been evaluated.",
        "",
        f"- Source cross-layer materialization ID: `{projection.source_cross_layer_materialization_id}`",
        f"- Source candidate materialization ID: `{projection.source_candidate_materialization_id}`",
        f"- Source candidate projection ID: `{projection.source_candidate_projection_id}`",
        f"- Requirement projection ID: `{projection.id}`",
        f"- Requirement materialization ID: `{source.id}`",
        f"- Candidate requirement count: {len(projection.candidate_requirements)}",
        f"- Binding requirement count: {len(projection.binding_requirements)}",
        "",
    ]
    for index, item in enumerate(projection.candidate_requirements, 1):
        lines.extend((
            f"## Candidate Requirement {index}", "",
            f"- Requirement ID: `{item.id}`",
            f"- Source case candidate ID: `{item.source_case_candidate_id}`",
            f"- Source obligation: `{item.source_obligation.value}`",
            f"- Required evidence kind: `{item.evidence_requirement_kind.value}`",
            "- Position candidate IDs:",
            *(f"  - `{value}`" for value in item.subject_position_candidate_ids),
            "- Fused fact node IDs:",
            *(f"  - `{value}`" for value in item.subject_fused_fact_node_ids),
            "- Order witness IDs:",
            *(f"  - `{value}`" for value in item.subject_order_witness_ids),
            "",
        ))
    for index, item in enumerate(projection.binding_requirements, 1):
        lines.extend((
            f"## Binding Requirement {index}", "",
            f"- Requirement ID: `{item.id}`",
            f"- Source binding ID: `{item.source_cross_layer_binding_id}`",
            f"- Source hardware reference ID: `{item.source_hardware_reference_id}`",
            f"- Source obligation: `{item.source_obligation.value}`",
            f"- Required evidence kind: `{item.evidence_requirement_kind.value}`",
            "",
        ))
    lines.extend((
        "Requirement != Evidence.", "",
        "Required Evidence Kind != Available Evidence.", "",
        "Projection Integrity != Source Referential Integrity.", "",
        "No RuntimeObservation was inspected and no VerificationRecord was created.", "",
    ))
    return "\n".join(lines)


def render_cross_layer_verification_requirement_graph_dot(materialization) -> str:
    """Render only source subjects and their objective evidence needs."""

    projection = _detached(materialization).projection
    lines = [
        "digraph cross_layer_verification_requirements {",
        "  rankdir=LR;",
        '  graph [label="Cross-Layer Verification Requirements", labelloc="t"];',
        '  node [shape=box, fontname="sans-serif"];',
        '  edge [fontname="sans-serif"];',
        '  boundary [shape=note, label="Requirements only; no evidence has been evaluated."];',
    ]
    subjects: dict[tuple[str, str], str] = {}
    requirements = [*projection.candidate_requirements, *projection.binding_requirements]
    for index, item in enumerate(requirements, 1):
        if hasattr(item, "source_cross_layer_binding_id"):
            key = ("binding", item.source_cross_layer_binding_id)
            label = f"Cross-Layer Binding\n{item.source_cross_layer_binding_id}"
        else:
            key = ("candidate", item.source_case_candidate_id)
            label = f"Case Candidate\n{item.source_case_candidate_id}"
        if key not in subjects:
            subjects[key] = f"subject_{len(subjects) + 1}"
            lines.append(f'  {subjects[key]} [label="{escape_dot_string(label)}"];')
        requirement_name = f"requirement_{index}"
        lines.append(f'  {requirement_name} [label="{escape_dot_string(item.evidence_requirement_kind.value)}\\n{escape_dot_string(item.id)}"];')
        lines.append(f'  {subjects[key]} -> {requirement_name} [label="requires objective evidence"];')
    lines.extend(("}", ""))
    return "\n".join(lines)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def export_cross_layer_verification_requirement_artifact_bundle(
    *, materialization: StaticCrossLayerVerificationRequirementMaterialization,
    output_directory: Path, include_svg: bool = True,
) -> CrossLayerVerificationRequirementArtifactBundleResult:
    """Write one deterministic, presentation-only requirement bundle."""

    source = _detached(materialization)
    outputs = {
        "verification_requirements.json": render_cross_layer_verification_requirement_projection_json(source),
        "verification_requirements_summary.md": render_cross_layer_verification_requirement_summary_markdown(source),
        "verification_requirements.dot": render_cross_layer_verification_requirement_graph_dot(source),
    }
    output_directory.mkdir(parents=True, exist_ok=True)
    for filename, content in outputs.items():
        (output_directory / filename).write_text(content, encoding="utf-8")
    manifest = {
        "architecture": source.projection.architecture.value,
        "artifact_id": source.projection.artifact_id,
        "artifact_sha256": source.projection.artifact_sha256,
        "files": {name: {"byte_size": len(outputs[name].encode("utf-8")), "sha256": _sha(outputs[name])} for name in _TEXT_FILENAMES},
        "instruction_set": source.projection.instruction_set,
        "requirement_materialization_id": source.id,
        "requirement_projection_id": source.projection.id,
        "source_cross_layer_materialization_id": source.source_cross_layer_candidate_materialization_id,
    }
    (output_directory / "manifest.json").write_text(_json(manifest), encoding="utf-8")
    svg_files: list[str] = []
    if include_svg and render_dot_to_svg_if_available(outputs["verification_requirements.dot"], output_directory / "verification_requirements.svg"):
        svg_files.append("verification_requirements.svg")
    return CrossLayerVerificationRequirementArtifactBundleResult(files=(*_TEXT_FILENAMES, "manifest.json"), svg_files=tuple(svg_files))
