"""Deterministic presentation for static trigger candidate materializations."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from chipchain.analysis.static_analysis_artifact_export import (
    escape_dot_string,
    render_dot_to_svg_if_available,
)
from chipchain.analysis.static_trigger_candidate_matching import (
    StaticTriggerCandidateMaterialization,
)


_TEXT_FILENAMES = (
    "candidate_projection.json",
    "candidate_summary.md",
    "candidate_witness.dot",
)


@dataclass(frozen=True)
class StaticTriggerCandidateArtifactBundleResult:
    """Names written by one static-candidate inspection export."""

    files: tuple[str, ...]
    svg_files: tuple[str, ...]


def _detached_materialization(
    value: StaticTriggerCandidateMaterialization,
) -> StaticTriggerCandidateMaterialization:
    return StaticTriggerCandidateMaterialization.model_validate(
        value.model_dump(mode="json")
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ) + "\n"


def render_static_trigger_candidate_projection_json(
    materialization: StaticTriggerCandidateMaterialization,
) -> str:
    """Render the internally valid candidate projection as canonical JSON."""

    source = _detached_materialization(materialization)
    return _canonical_json(source.projection.model_dump(mode="json"))


def render_static_trigger_candidate_summary_markdown(
    materialization: StaticTriggerCandidateMaterialization,
) -> str:
    """Render exact candidate bindings and unresolved obligations."""

    source = _detached_materialization(materialization)
    projection = source.projection
    patterns = {
        pattern.id: pattern
        for pattern in source.source_pattern_catalog_snapshot.patterns
    }
    lines = [
        "# Static Trigger Candidates",
        "",
        "This bundle is owned, synthetic, and benign.",
        "",
        f"- Architecture: `{projection.architecture.value}`",
        f"- Instruction set: `{projection.instruction_set}`",
        f"- Firmware artifact ID: `{projection.artifact_id}`",
        f"- Firmware artifact SHA-256: `{projection.artifact_sha256}`",
        "- Fused graph materialization ID: "
        f"`{projection.source_fused_graph_materialization_id}`",
        f"- Pattern catalog ID: `{projection.source_pattern_catalog_id}`",
        f"- Candidate projection ID: `{projection.id}`",
        f"- Candidate materialization ID: `{source.id}`",
        f"- Case candidate count: {len(projection.case_candidates)}",
        "",
    ]
    for index, candidate in enumerate(projection.case_candidates, start=1):
        pattern = patterns[candidate.source_pattern_id]
        lines.extend(
            (
                f"## Candidate {index}: {candidate.case_reference_id}",
                "",
                f"- Pattern: `{pattern.pattern_name}`",
                f"- Pattern ID: `{candidate.source_pattern_id}`",
                f"- Case: `{candidate.case_reference_id}`",
                f"- Case ID: `{candidate.source_case_id}`",
                f"- Candidate ID: `{candidate.id}`",
                f"- Function: `{candidate.function_address}`",
                "",
                "### Positions",
                "",
            )
        )
        for position in candidate.position_candidates:
            lines.extend(
                (
                    f"{position.position_index}.",
                    f"   - Predicate ID: `{position.source_predicate_id}`",
                    f"   - Operation: `{position.operation.value}`",
                    "   - Semantic fact node ID: "
                    f"`{position.source_fused_fact_node_id}`",
                    "   - Semantic source fact IDs: "
                    f"`{', '.join(position.source_semantic_fact_ids)}`",
                    "   - Instruction address: "
                    f"`{position.instruction_address}`",
                    f"   - Basic-block address: `{position.basic_block_address}`",
                    "",
                )
            )
        lines.extend(("### Static order witnesses", ""))
        if not candidate.order_witnesses:
            lines.extend(("None.", ""))
        for witness in candidate.order_witnesses:
            lines.extend(
                (
                    f"- {witness.from_position_index} -> "
                    f"{witness.to_position_index}",
                    f"  - Basis: `{witness.order_basis.value}`",
                    "  - Block-node path: "
                    f"`{' -> '.join(witness.witness_basic_block_node_ids)}`",
                    "  - CFG relation IDs: "
                    f"`{', '.join(witness.witness_cfg_relation_ids) or 'None'}`",
                )
            )
        lines.extend(("", "### Remaining objective obligations", ""))
        lines.extend(
            f"- `{obligation.value}`"
            for obligation in candidate.remaining_objective_obligations
        )
        lines.extend(
            (
                "",
                "Candidate interpretation: static structural pattern "
                "candidate only.",
                "",
            )
        )
    lines.extend(
        (
            "Candidate != Runtime Execution.",
            "",
            "Static CFG Witness != Runtime Path.",
            "",
            "CFG Reachability != Symbolic Feasibility.",
            "",
            "Pattern Candidate != Triggerability.",
            "",
            "Pattern Hardware Reference != Candidate Hardware Binding.",
            "",
            "Program Order Candidate != Runtime Order.",
            "",
            "Unresolved Requirement != Satisfied Requirement.",
            "",
            "Candidate != AttackChain.",
            "",
        )
    )
    return "\n".join(lines)


def render_static_trigger_candidate_witness_dot(
    materialization: StaticTriggerCandidateMaterialization,
) -> str:
    """Render exact selected facts and static-order witnesses as DOT."""

    source = _detached_materialization(materialization)
    lines = [
        "digraph static_trigger_candidates {",
        "  rankdir=LR;",
        '  graph [label="Static Trigger Candidates", labelloc="t"];',
        '  node [shape=box, fontname="sans-serif"];',
        '  edge [fontname="sans-serif"];',
        '  boundary [shape=note, label="Static candidate only; runtime '
        'execution and feasibility remain unresolved."];',
    ]
    for case_index, candidate in enumerate(
        source.projection.case_candidates, start=1
    ):
        names = {
            position.id: f"case_{case_index}_position_{position.position_index}"
            for position in candidate.position_candidates
        }
        lines.append(f"  subgraph cluster_{case_index} {{")
        lines.append(
            '    label="'
            f'{escape_dot_string(candidate.case_reference_id)}";'
        )
        for position in candidate.position_candidates:
            label = (
                f"Position {position.position_index}\\n"
                f"{position.operation.value}\\n"
                f"{position.instruction_address}"
            )
            lines.append(
                f"    {names[position.id]} "
                f'[label="{escape_dot_string(label)}"];'
            )
        for witness in candidate.order_witnesses:
            label = (
                "same-block static order"
                if witness.order_basis.value.startswith("same_basic_block")
                else "static CFG witness"
            )
            lines.append(
                f"    {names[witness.source_position_candidate_id]} -> "
                f"{names[witness.target_position_candidate_id]} "
                f'[label="{label}"];'
            )
        lines.append("  }")
    lines.extend(("}", ""))
    return "\n".join(lines)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _manifest_text(
    materialization: StaticTriggerCandidateMaterialization,
    outputs: dict[str, str],
) -> str:
    projection = materialization.projection
    return _canonical_json(
        {
            "architecture": projection.architecture.value,
            "artifact_id": projection.artifact_id,
            "artifact_sha256": projection.artifact_sha256,
            "candidate_materialization_id": materialization.id,
            "candidate_projection_id": projection.id,
            "files": {
                filename: {
                    "byte_size": len(outputs[filename].encode("utf-8")),
                    "sha256": _sha256_text(outputs[filename]),
                }
                for filename in _TEXT_FILENAMES
            },
            "instruction_set": projection.instruction_set,
            "source_fused_graph_materialization_id": (
                projection.source_fused_graph_materialization_id
            ),
            "source_pattern_catalog_id": projection.source_pattern_catalog_id,
        }
    )


def export_static_trigger_candidate_artifact_bundle(
    *,
    materialization: StaticTriggerCandidateMaterialization,
    output_directory: Path,
    include_svg: bool = True,
) -> StaticTriggerCandidateArtifactBundleResult:
    """Write one deterministic static-candidate inspection bundle."""

    source = _detached_materialization(materialization)
    outputs = {
        "candidate_projection.json": (
            render_static_trigger_candidate_projection_json(source)
        ),
        "candidate_summary.md": (
            render_static_trigger_candidate_summary_markdown(source)
        ),
        "candidate_witness.dot": (
            render_static_trigger_candidate_witness_dot(source)
        ),
    }
    output_directory.mkdir(parents=True, exist_ok=True)
    for filename in _TEXT_FILENAMES:
        (output_directory / filename).write_text(
            outputs[filename], encoding="utf-8"
        )
    (output_directory / "manifest.json").write_text(
        _manifest_text(source, outputs), encoding="utf-8"
    )
    svg_files: list[str] = []
    if include_svg and render_dot_to_svg_if_available(
        outputs["candidate_witness.dot"],
        output_directory / "candidate_witness.svg",
    ):
        svg_files.append("candidate_witness.svg")
    return StaticTriggerCandidateArtifactBundleResult(
        files=(*_TEXT_FILENAMES, "manifest.json"),
        svg_files=tuple(svg_files),
    )
