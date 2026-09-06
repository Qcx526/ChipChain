"""Deterministic presentation of neutral candidate runtime evidence."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from chipchain.analysis.static_analysis_artifact_export import (
    escape_dot_string,
    render_dot_to_svg_if_available,
)
from chipchain.verification.candidate_runtime_evidence_binding import (
    CandidateRuntimeEvidenceMaterialization,
)


_TEXT_FILENAMES = (
    "runtime_evidence.json",
    "runtime_evidence_summary.md",
    "runtime_evidence.dot",
)


@dataclass(frozen=True)
class CandidateRuntimeEvidenceArtifactBundleResult:
    """Exact files emitted by one presentation-only export."""

    files: tuple[str, ...]
    svg_files: tuple[str, ...]


def _detached(
    value: CandidateRuntimeEvidenceMaterialization,
) -> CandidateRuntimeEvidenceMaterialization:
    return CandidateRuntimeEvidenceMaterialization.model_validate(
        value.model_dump(mode="json")
    )


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def render_candidate_runtime_evidence_projection_json(
    materialization: CandidateRuntimeEvidenceMaterialization,
) -> str:
    """Render only the deterministic evidence projection."""

    return _json(_detached(materialization).projection.model_dump(mode="json"))


def render_candidate_runtime_evidence_summary_markdown(
    materialization: CandidateRuntimeEvidenceMaterialization,
) -> str:
    """Render exact observation provenance without evaluation language."""

    source = _detached(materialization)
    projection = source.projection
    requirements = {
        item.id: item
        for item in (
            source.source_requirement_materialization_snapshot.projection
            .candidate_requirements
        )
    }
    lines = [
        "# Candidate Runtime Evidence",
        "",
        "Runtime evidence only; requirement satisfaction has not been evaluated.",
        "",
        "Endpoint instruction evidence does not establish runtime witness order.",
        "Runtime order evidence does not establish CFG path feasibility.",
        "Path acquisition gap records absence of B1 runtime-order evidence only. It is not a feasibility verdict.",
        "",
        f"- Requirement materialization ID: `{projection.source_requirement_materialization_id}`",
        f"- Requirement projection ID: `{projection.source_requirement_projection_id}`",
        f"- Runtime evidence projection ID: `{projection.id}`",
        f"- Runtime evidence materialization ID: `{source.id}`",
        f"- Runtime trace count: {len(projection.source_runtime_trace_ids)}",
        f"- Instruction evidence count: {len(projection.instruction_evidence)}",
        f"- Runtime order evidence count: {len(projection.order_evidence)}",
        f"- Requirement binding count: {len(projection.requirement_evidence_bindings)}",
        f"- Evidence gap count: {len(projection.evidence_gaps)}",
        f"- Out-of-scope hardware requirement count: {len(projection.out_of_scope_requirement_ids)}",
        "",
    ]
    lines.extend(f"- {value}" for value in projection.diagnostic_codes)
    lines.append("")
    for index, item in enumerate(projection.instruction_evidence, 1):
        lines.extend(
            (
                f"## Instruction Observation Artifact {index}",
                "",
                f"- Evidence ID: `{item.id}`",
                f"- Runtime trace ID: `{item.source_runtime_trace_id}`",
                f"- Runtime observation ID: `{item.source_runtime_observation_id}`",
                f"- Sequence index: {item.observation_sequence_index}",
                f"- vCPU index: {item.observation_vcpu_index}",
                f"- PC: `{item.observed_pc.value}`",
                "- Position candidate IDs:",
                *(f"  - `{value}`" for value in item.source_position_candidate_ids),
                "- Fused fact node IDs:",
                *(f"  - `{value}`" for value in item.source_fused_fact_node_ids),
                "",
            )
        )
    for index, item in enumerate(projection.order_evidence, 1):
        lines.extend(
            (
                f"## Endpoint Runtime Order Artifact {index}",
                "",
                f"- Evidence ID: `{item.id}`",
                f"- Static order witness ID: `{item.source_static_order_witness_id}`",
                f"- Runtime trace ID: `{item.source_runtime_trace_id}`",
                f"- Source observation ID: `{item.source_runtime_observation_id}`",
                f"- Target observation ID: `{item.target_runtime_observation_id}`",
                f"- Source sequence index: {item.source_sequence_index}",
                f"- Target sequence index: {item.target_sequence_index}",
                f"- vCPU index: {item.vcpu_index}",
                f"- Source PC: `{item.expected_source_instruction_address.value}`",
                f"- Target PC: `{item.expected_target_instruction_address.value}`",
                f"- Source position candidate ID: `{item.source_position_candidate_id}`",
                f"- Target position candidate ID: `{item.target_position_candidate_id}`",
                f"- Source fused fact node ID: `{item.source_fused_fact_node_id}`",
                f"- Target fused fact node ID: `{item.target_fused_fact_node_id}`",
                "",
            )
        )
    for index, item in enumerate(projection.requirement_evidence_bindings, 1):
        requirement = requirements[item.source_requirement_id]
        lines.extend(
            (
                f"## Requirement-Relevance Binding {index}",
                "",
                f"- Binding ID: `{item.id}`",
                f"- Requirement ID: `{item.source_requirement_id}`",
                f"- Case candidate ID: `{item.source_case_candidate_id}`",
                f"- Requirement kind: `{item.source_requirement_kind.value}`",
                f"- Runtime evidence ID: `{item.source_runtime_evidence_id}`",
                "- Requirement subject fused fact IDs:",
                *(
                    f"  - `{value}`"
                    for value in requirement.subject_fused_fact_node_ids
                ),
                "- Requirement subject order witness IDs:",
                *(
                    f"  - `{value}`"
                    for value in requirement.subject_order_witness_ids
                ),
                "",
            )
        )
    for item in projection.evidence_gaps:
        lines.append(
            f"- Evidence gap `{item.id}`: requirement `{item.source_requirement_id}` / `{item.reason.value}`"
        )
    if projection.evidence_gaps:
        lines.append("")
    lines.extend(
        (
            "Runtime Observation != Requirement Satisfaction.",
            "",
            "Observed Endpoint Order != Exact CFG Path Observation.",
            "",
            "Evidence Binding != Evidence Evaluation.",
            "",
        )
    )
    return "\n".join(lines)


def render_candidate_runtime_evidence_graph_dot(
    materialization: CandidateRuntimeEvidenceMaterialization,
) -> str:
    """Render only exact observation/artifact/binding edges."""

    projection = _detached(materialization).projection
    lines = [
        "digraph candidate_runtime_evidence {",
        "  rankdir=LR;",
        '  graph [label="Candidate Runtime Evidence", labelloc="t"];',
        '  node [shape=box, fontname="sans-serif"];',
        '  edge [fontname="sans-serif"];',
        '  boundary [shape=note, label="Runtime evidence only; requirement satisfaction has not been evaluated."];',
        '  order_boundary [shape=note, label="Endpoint instruction evidence does not establish runtime witness order.\\nRuntime order evidence does not establish CFG path feasibility.\\nPath acquisition gap records absence of B1 runtime-order evidence only. It is not a feasibility verdict."];',
    ]
    evidence_names: dict[str, str] = {}
    observation_names: dict[str, str] = {}

    def observation_name(observation_id: str) -> str:
        if observation_id not in observation_names:
            name = f"observation_{len(observation_names) + 1}"
            observation_names[observation_id] = name
            lines.append(
                f'  {name} [label="{escape_dot_string("RuntimeObservation\\n" + observation_id)}"];'
            )
        return observation_names[observation_id]

    for item in projection.instruction_evidence:
        evidence_name = f"evidence_{len(evidence_names) + 1}"
        evidence_names[item.id] = evidence_name
        lines.append(
            f'  {evidence_name} [label="{escape_dot_string(item.evidence_kind.value + chr(10) + item.id)}"];'
        )
        lines.append(
            f'  {observation_name(item.source_runtime_observation_id)} -> {evidence_name} [label="exact runtime observation"];'
        )
    for item in projection.order_evidence:
        evidence_name = f"evidence_{len(evidence_names) + 1}"
        evidence_names[item.id] = evidence_name
        lines.append(
            f'  {evidence_name} [label="{escape_dot_string(item.evidence_kind.value + chr(10) + item.id)}"];'
        )
        for observation_id in (
            item.source_runtime_observation_id,
            item.target_runtime_observation_id,
        ):
            lines.append(
                f'  {observation_name(observation_id)} -> {evidence_name} [label="exact runtime observation"];'
            )
    requirement_names: dict[str, str] = {}
    for item in projection.requirement_evidence_bindings:
        if item.source_requirement_id not in requirement_names:
            name = f"requirement_{len(requirement_names) + 1}"
            requirement_names[item.source_requirement_id] = name
            lines.append(
                f'  {name} [label="{escape_dot_string("Verification Requirement\\n" + item.source_requirement_id)}"];'
            )
        lines.append(
            f'  {evidence_names[item.source_runtime_evidence_id]} -> {requirement_names[item.source_requirement_id]} [label="exact subject binding"];'
        )
    lines.extend(("}", ""))
    return "\n".join(lines)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def export_candidate_runtime_evidence_artifact_bundle(
    *,
    materialization: CandidateRuntimeEvidenceMaterialization,
    output_directory: Path,
    include_svg: bool = True,
) -> CandidateRuntimeEvidenceArtifactBundleResult:
    """Write one deterministic presentation-only runtime evidence bundle."""

    source = _detached(materialization)
    outputs = {
        "runtime_evidence.json": render_candidate_runtime_evidence_projection_json(
            source
        ),
        "runtime_evidence_summary.md": (
            render_candidate_runtime_evidence_summary_markdown(source)
        ),
        "runtime_evidence.dot": render_candidate_runtime_evidence_graph_dot(source),
    }
    output_directory.mkdir(parents=True, exist_ok=True)
    for filename, content in outputs.items():
        (output_directory / filename).write_text(content, encoding="utf-8")
    manifest = {
        "architecture": source.projection.architecture.value,
        "artifact_id": source.projection.artifact_id,
        "artifact_sha256": source.projection.artifact_sha256,
        "files": {
            name: {
                "byte_size": len(outputs[name].encode("utf-8")),
                "sha256": _sha256(outputs[name]),
            }
            for name in _TEXT_FILENAMES
        },
        "instruction_set": source.projection.instruction_set,
        "runtime_evidence_materialization_id": source.id,
        "runtime_evidence_projection_id": source.projection.id,
        "source_requirement_materialization_id": (
            source.source_requirement_materialization_id
        ),
        "source_runtime_trace_ids": source.projection.source_runtime_trace_ids,
    }
    (output_directory / "manifest.json").write_text(
        _json(manifest), encoding="utf-8"
    )
    svg_files: list[str] = []
    if include_svg and render_dot_to_svg_if_available(
        outputs["runtime_evidence.dot"],
        output_directory / "runtime_evidence.svg",
    ):
        svg_files.append("runtime_evidence.svg")
    return CandidateRuntimeEvidenceArtifactBundleResult(
        files=(*_TEXT_FILENAMES, "manifest.json"),
        svg_files=tuple(svg_files),
    )
