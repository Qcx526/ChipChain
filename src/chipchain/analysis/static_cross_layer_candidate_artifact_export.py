"""Deterministic presentation for static cross-layer reference candidates."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from chipchain.analysis.static_analysis_artifact_export import (
    escape_dot_string,
    render_dot_to_svg_if_available,
)
from chipchain.analysis.static_cross_layer_candidate_binding import (
    StaticCrossLayerCandidateMaterialization,
)
from chipchain.analysis.static_hardware_reference_models import (
    StaticDocumentedErratumHardwareReference,
)


_TEXT_FILENAMES = (
    "cross_layer_projection.json",
    "cross_layer_summary.md",
    "cross_layer_graph.dot",
)


@dataclass(frozen=True)
class StaticCrossLayerCandidateArtifactBundleResult:
    """Names written by one static cross-layer inspection export."""

    files: tuple[str, ...]
    svg_files: tuple[str, ...]


def _detached_materialization(
    value: StaticCrossLayerCandidateMaterialization,
) -> StaticCrossLayerCandidateMaterialization:
    return StaticCrossLayerCandidateMaterialization.model_validate(
        value.model_dump(mode="json")
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ) + "\n"


def render_static_cross_layer_candidate_projection_json(
    materialization: StaticCrossLayerCandidateMaterialization,
) -> str:
    """Render the internally valid cross-layer projection as canonical JSON."""

    source = _detached_materialization(materialization)
    return _canonical_json(source.projection.model_dump(mode="json"))


def render_static_cross_layer_candidate_summary_markdown(
    materialization: StaticCrossLayerCandidateMaterialization,
) -> str:
    """Render exact source-declared bindings and unresolved obligations."""

    source = _detached_materialization(materialization)
    projection = source.projection
    reference_by_record_id = {
        reference.id: reference
        for reference in source.source_hardware_reference_catalog_snapshot.references
    }
    lines = [
        "# Static Cross-Layer Reference Candidates",
        "",
        "This output records source-declared reference candidates only.",
        "",
        f"- Architecture: `{projection.architecture.value}`",
        f"- Instruction set: `{projection.instruction_set}`",
        f"- Firmware artifact ID: `{projection.artifact_id}`",
        f"- Firmware artifact SHA-256: `{projection.artifact_sha256}`",
        "- Candidate materialization ID: "
        f"`{projection.source_candidate_materialization_id}`",
        "- Hardware reference catalog ID: "
        f"`{projection.source_hardware_reference_catalog_id}`",
        f"- Cross-layer projection ID: `{projection.id}`",
        f"- Cross-layer materialization ID: `{source.id}`",
        f"- Binding count: {len(projection.bindings)}",
        f"- Unresolved reference count: {len(projection.unresolved_references)}",
        "",
    ]
    if all(
        getattr(reference, "owned", False)
        and getattr(reference, "synthetic", False)
        and getattr(reference, "benign", False)
        for reference in reference_by_record_id.values()
    ):
        lines.extend(("Dataset provenance: owned, synthetic, and benign.", ""))
    for index, binding in enumerate(projection.bindings, start=1):
        reference = reference_by_record_id[
            binding.source_hardware_reference_record_id
        ]
        lines.extend(
            (
                f"## Binding {index}",
                "",
                f"- Binding ID: `{binding.id}`",
                f"- Case candidate ID: `{binding.source_case_candidate_id}`",
                f"- Source pattern ID: `{binding.source_pattern_id}`",
                "- Pattern-declared hardware reference ID: "
                f"`{binding.source_hardware_reference_id}`",
                f"- Hardware reference record ID: `{reference.id}`",
                f"- Reference kind: `{reference.reference_kind.value}`",
                "- Binding semantics: "
                f"`{binding.binding_semantics.value}`",
            )
        )
        if isinstance(reference, StaticDocumentedErratumHardwareReference):
            erratum = reference.source_documented_erratum_snapshot
            lines.extend(
                (
                    "- Documented erratum object ID: "
                    f"`{erratum.id}`",
                    f"- Documented CVE association: `{erratum.cve_id}`",
                    "- Vendor-documented erratum ID: "
                    f"`{erratum.authoritative_source.erratum_id}`",
                    f"- Vendor-documented processor: `{erratum.processor}`",
                    "- Vendor-documented possible effect: "
                    f"`{erratum.documented_effect.kind.value}`",
                    "- Vendor-documented revision dispositions:",
                )
            )
            lines.extend(
                f"  - `{item.revision}`: `{item.disposition.value}`"
                for item in erratum.revision_records
            )
        lines.extend(("", "### Candidate remaining obligations", ""))
        lines.extend(
            f"- `{item.value}`"
            for item in binding.candidate_remaining_objective_obligations
        )
        lines.extend(("", "### Cross-layer remaining obligations", ""))
        lines.extend(
            f"- `{item.value}`"
            for item in binding.cross_layer_remaining_objective_obligations
        )
        lines.append("")
    if projection.unresolved_references:
        lines.extend(("## Unresolved source-declared references", ""))
        for unresolved in projection.unresolved_references:
            lines.extend(
                (
                    f"- Case candidate: `{unresolved.source_case_candidate_id}`",
                    "  - Hardware reference: "
                    f"`{unresolved.source_hardware_reference_id}`",
                    f"  - Catalog resolution: `{unresolved.reason.value}`",
                )
            )
        lines.append("")
    lines.extend(
        (
            "Static cross-layer reference candidate only; runtime execution, "
            "target applicability, and hardware effect remain unresolved.",
            "",
            "Cross-Layer Reference Candidate != Vulnerability Verification.",
            "",
            "Pattern Hardware Reference != Hardware Trigger Observation.",
            "",
            "Documented Affected Revision != Observed Target Revision.",
            "",
            "Documented Possible Effect != Runtime Observed Effect.",
            "",
            "Candidate -> Erratum Reference != Candidate Triggers Erratum.",
            "",
            "CVE Association != Firmware Vulnerability Verdict.",
            "",
            "Static Candidate != Runtime Execution.",
            "",
            "Static CFG Witness != Runtime Path.",
            "",
            "Unresolved Requirement != Satisfied Requirement.",
            "",
            "Cross-Layer Candidate != Verified AttackChain.",
            "",
        )
    )
    return "\n".join(lines)


def render_static_cross_layer_candidate_graph_dot(
    materialization: StaticCrossLayerCandidateMaterialization,
) -> str:
    """Render only exact candidate/reference bindings and documented metadata."""

    source = _detached_materialization(materialization)
    reference_by_record_id = {
        reference.id: reference
        for reference in source.source_hardware_reference_catalog_snapshot.references
    }
    lines = [
        "digraph static_cross_layer_candidates {",
        "  rankdir=LR;",
        '  graph [label="Static Cross-Layer Reference Candidates", labelloc="t"];',
        '  node [shape=box, fontname="sans-serif"];',
        '  edge [fontname="sans-serif"];',
        '  boundary [shape=note, label="Static cross-layer reference candidate '
        'only;\\nruntime execution, target applicability, and hardware effect '
        'remain unresolved."];',
    ]
    candidate_names: dict[str, str] = {}
    reference_names: dict[str, str] = {}
    cve_names: dict[str, str] = {}
    for binding in source.projection.bindings:
        candidate_is_new = binding.source_case_candidate_id not in candidate_names
        if candidate_is_new:
            candidate_names[binding.source_case_candidate_id] = (
                f"candidate_{len(candidate_names) + 1}"
            )
        candidate_name = candidate_names[binding.source_case_candidate_id]
        reference_is_new = (
            binding.source_hardware_reference_record_id not in reference_names
        )
        if reference_is_new:
            reference_names[binding.source_hardware_reference_record_id] = (
                f"reference_{len(reference_names) + 1}"
            )
        reference_name = reference_names[
            binding.source_hardware_reference_record_id
        ]
        if candidate_is_new:
            lines.append(
                f'  {candidate_name} [label="Firmware Static Candidate\\n'
                f'{escape_dot_string(binding.source_case_candidate_id)}"];'
            )
        reference = reference_by_record_id[
            binding.source_hardware_reference_record_id
        ]
        if reference_is_new:
            if isinstance(reference, StaticDocumentedErratumHardwareReference):
                erratum = reference.source_documented_erratum_snapshot
                label = (
                    f"Arm {erratum.processor} Erratum "
                    f"{erratum.authoritative_source.erratum_id}\n"
                    "documented source reference"
                )
            else:
                label = f"Owned Synthetic Hardware Reference\n{reference.title}"
            lines.append(
                f'  {reference_name} [label="{escape_dot_string(label)}"];'
            )
        lines.append(
            f"  {candidate_name} -> {reference_name} "
            '[label="pattern-declared reference"];'
        )
        if isinstance(reference, StaticDocumentedErratumHardwareReference):
            cve_id = reference.cve_id
            cve_is_new = cve_id not in cve_names
            if cve_is_new:
                cve_names[cve_id] = f"cve_{len(cve_names) + 1}"
            cve_name = cve_names[cve_id]
            if cve_is_new:
                lines.append(
                    f'  {cve_name} [label="{escape_dot_string(cve_id)}\\n'
                    'documented association"];'
                )
            lines.append(
                f"  {reference_name} -> {cve_name} "
                '[label="documented CVE association"];'
            )
    lines.extend(("}", ""))
    return "\n".join(lines)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _manifest_text(
    materialization: StaticCrossLayerCandidateMaterialization,
    outputs: dict[str, str],
) -> str:
    projection = materialization.projection
    return _canonical_json(
        {
            "architecture": projection.architecture.value,
            "artifact_id": projection.artifact_id,
            "artifact_sha256": projection.artifact_sha256,
            "cross_layer_materialization_id": materialization.id,
            "cross_layer_projection_id": projection.id,
            "files": {
                filename: {
                    "byte_size": len(outputs[filename].encode("utf-8")),
                    "sha256": _sha256_text(outputs[filename]),
                }
                for filename in _TEXT_FILENAMES
            },
            "instruction_set": projection.instruction_set,
            "source_candidate_materialization_id": (
                projection.source_candidate_materialization_id
            ),
            "source_hardware_reference_catalog_id": (
                projection.source_hardware_reference_catalog_id
            ),
        }
    )


def export_static_cross_layer_candidate_artifact_bundle(
    *,
    materialization: StaticCrossLayerCandidateMaterialization,
    output_directory: Path,
    include_svg: bool = True,
) -> StaticCrossLayerCandidateArtifactBundleResult:
    """Write one deterministic static cross-layer inspection bundle."""

    source = _detached_materialization(materialization)
    outputs = {
        "cross_layer_projection.json": (
            render_static_cross_layer_candidate_projection_json(source)
        ),
        "cross_layer_summary.md": (
            render_static_cross_layer_candidate_summary_markdown(source)
        ),
        "cross_layer_graph.dot": (
            render_static_cross_layer_candidate_graph_dot(source)
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
        outputs["cross_layer_graph.dot"],
        output_directory / "cross_layer_graph.svg",
    ):
        svg_files.append("cross_layer_graph.svg")
    return StaticCrossLayerCandidateArtifactBundleResult(
        files=(*_TEXT_FILENAMES, "manifest.json"),
        svg_files=tuple(svg_files),
    )
