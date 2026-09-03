"""Deterministic presentation of frozen static-analysis source artifacts."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from chipchain.analysis.static_program_structure_models import (
    StaticProgramStructureInventory,
)
from chipchain.analysis.static_semantic_graph_models import (
    StaticSemanticGraphNode,
    StaticSemanticGraphNodeKind,
    StaticSemanticGraphRelationKind,
)
from chipchain.analysis.static_semantic_graph_projection import (
    StaticSemanticGraphProjectionMaterialization,
)
from chipchain.analysis.static_semantic_models import (
    StaticSemanticInstructionFact,
    StaticSemanticInventory,
    StaticSemanticOperation,
)


_TEXT_FILENAMES = (
    "semantic_inventory.json",
    "semantic_graph.json",
    "semantic_summary.md",
    "semantic_graph.dot",
    "structure_inventory.json",
    "structure_summary.md",
    "structure_graph.dot",
    "inspection_summary.md",
)


@dataclass(frozen=True)
class StaticAnalysisArtifactBundleResult:
    """Names of files written by one presentation-only bundle export."""

    files: tuple[str, ...]
    svg_files: tuple[str, ...]


def _canonical_json(value: object) -> str:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


def _detached_semantic_inventory(
    inventory: StaticSemanticInventory,
) -> StaticSemanticInventory:
    return StaticSemanticInventory.model_validate(
        inventory.model_dump(mode="json")
    )


def _detached_graph_materialization(
    materialization: StaticSemanticGraphProjectionMaterialization,
) -> StaticSemanticGraphProjectionMaterialization:
    return StaticSemanticGraphProjectionMaterialization.model_validate(
        materialization.model_dump(mode="json")
    )


def _detached_structure_inventory(
    inventory: StaticProgramStructureInventory,
) -> StaticProgramStructureInventory:
    return StaticProgramStructureInventory.model_validate(
        inventory.model_dump(mode="json")
    )


def render_static_semantic_inventory_json(
    inventory: StaticSemanticInventory,
) -> str:
    """Render an exact frozen semantic inventory as canonical JSON."""

    source = _detached_semantic_inventory(inventory)
    return _canonical_json(source.model_dump(mode="json"))


def render_static_semantic_graph_json(
    materialization: StaticSemanticGraphProjectionMaterialization,
) -> str:
    """Render an exact frozen graph materialization as canonical JSON."""

    source = _detached_graph_materialization(materialization)
    return _canonical_json(source.model_dump(mode="json"))


def render_static_program_structure_inventory_json(
    inventory: StaticProgramStructureInventory,
) -> str:
    """Render an exact frozen structure inventory as canonical JSON."""

    source = _detached_structure_inventory(inventory)
    return _canonical_json(source.model_dump(mode="json"))


def _markdown_cell(value: object) -> str:
    if value is None:
        return "None"
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", "<br>")
    )


def _attributes_text(attributes: list) -> str:
    if not attributes:
        return "None"
    return "; ".join(
        f"{item.name.value}={item.value}" for item in attributes
    )


def _semantic_graph_counts(
    materialization: StaticSemanticGraphProjectionMaterialization,
) -> tuple[dict[StaticSemanticGraphNodeKind, int], dict[StaticSemanticGraphRelationKind, int], int]:
    projection = materialization.projection
    node_counts = Counter(node.kind for node in projection.nodes)
    relation_counts = Counter(
        relation.relation_kind for relation in projection.relations
    )
    contained_fact_nodes = {
        relation.target_node_id
        for relation in projection.relations
        if relation.relation_kind
        in {
            StaticSemanticGraphRelationKind
            .BASIC_BLOCK_CONTAINS_SEMANTIC_FACT,
            StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT,
        }
    }
    uncontained = sum(
        node.kind is StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT
        and node.id not in contained_fact_nodes
        for node in projection.nodes
    )
    return dict(node_counts), dict(relation_counts), uncontained


def render_static_semantic_summary_markdown(
    inventory: StaticSemanticInventory,
    graph_materialization: StaticSemanticGraphProjectionMaterialization,
) -> str:
    """Render semantic facts and frozen containment counts for inspection."""

    source = _detached_semantic_inventory(inventory)
    graph = _detached_graph_materialization(graph_materialization)
    if graph.source_inventory_snapshot != source:
        raise ValueError("semantic graph source snapshot does not match inventory")
    operation_counts = Counter(fact.operation for fact in source.facts)
    node_counts, relation_counts, uncontained = _semantic_graph_counts(graph)
    lines = [
        "# Static Semantic Inventory",
        "",
        f"- Artifact ID: `{source.artifact_id}`",
        f"- Artifact SHA-256: `{source.artifact_sha256}`",
        f"- Architecture: `{source.architecture.value}`",
        f"- Instruction set: `{source.instruction_set}`",
        f"- Decoder profile: `{source.decoder_profile_id}`",
        f"- Inventory ID: `{source.id}`",
        f"- Inventory scope: `{source.analysis_scope.value}`",
        "",
        "## Counts",
        "",
        f"- Semantic fact count: {len(source.facts)}",
        "",
        "### Operations",
        "",
        "| Operation | Count |",
        "|---|---:|",
    ]
    lines.extend(
        f"| `{operation.value}` | {operation_counts[operation]} |"
        for operation in StaticSemanticOperation
    )
    lines.extend(
        [
            "",
            "## Facts",
            "",
            "| Instruction address | Instruction bytes | Operation | Function name | Function address | Basic block address | Attributes |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for fact in source.facts:
        lines.append(
            "| "
            + " | ".join(
                (
                    f"`{fact.instruction_address}`",
                    f"`{fact.instruction_bytes}`",
                    f"`{fact.operation.value}`",
                    _markdown_cell(fact.function_name),
                    _markdown_cell(fact.function_address),
                    _markdown_cell(fact.basic_block_address),
                    _markdown_cell(_attributes_text(fact.attributes)),
                )
            )
            + " |"
        )
    projection = graph.projection
    lines.extend(
        [
            "",
            "## Static Semantic Graph",
            "",
            f"- Projection ID: `{projection.id}`",
            f"- Materialization ID: `{graph.id}`",
            "",
            "### Node counts",
            "",
            f"- FUNCTION: {node_counts.get(StaticSemanticGraphNodeKind.FUNCTION, 0)}",
            f"- BASIC_BLOCK: {node_counts.get(StaticSemanticGraphNodeKind.BASIC_BLOCK, 0)}",
            "- SEMANTIC_INSTRUCTION_FACT: "
            f"{node_counts.get(StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT, 0)}",
            "",
            "### Relation counts",
            "",
            "- FUNCTION_CONTAINS_BASIC_BLOCK: "
            f"{relation_counts.get(StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK, 0)}",
            "- BASIC_BLOCK_CONTAINS_SEMANTIC_FACT: "
            f"{relation_counts.get(StaticSemanticGraphRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT, 0)}",
            "- FUNCTION_CONTAINS_SEMANTIC_FACT: "
            f"{relation_counts.get(StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT, 0)}",
            f"- Uncontained semantic fact count: {uncontained}",
            "",
            "Static containment != runtime execution.",
            "",
            "Static containment != causality.",
            "",
        ]
    )
    return "\n".join(lines)


def escape_dot_string(value: object) -> str:
    """Escape one arbitrary value for a quoted Graphviz DOT string."""

    return (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\n")
        .replace("\n", "\\n")
    )


def _semantic_node_label(node: StaticSemanticGraphNode) -> str:
    if node.kind is StaticSemanticGraphNodeKind.FUNCTION:
        name = node.function_name if node.function_name is not None else "None"
        return f"Function\n{name}\n{node.function_address}"
    if node.kind is StaticSemanticGraphNodeKind.BASIC_BLOCK:
        return f"Basic Block\n{node.basic_block_address}"
    attributes = _attributes_text(node.attributes)
    suffix = "" if attributes == "None" else f"\n{attributes}"
    return f"{node.operation.value}\n{node.instruction_address}{suffix}"


def render_static_semantic_graph_dot(
    materialization: StaticSemanticGraphProjectionMaterialization,
) -> str:
    """Render only frozen semantic nodes and relations as Graphviz DOT."""

    source = _detached_graph_materialization(materialization)
    projection = source.projection
    node_names = {
        node.id: f"node_{index}"
        for index, node in enumerate(projection.nodes)
    }
    shapes = {
        StaticSemanticGraphNodeKind.FUNCTION: "box",
        StaticSemanticGraphNodeKind.BASIC_BLOCK: "ellipse",
        StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT: "note",
    }
    relation_labels = {
        StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK: (
            "contains block"
        ),
        StaticSemanticGraphRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT: (
            "contains semantic fact"
        ),
        StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT: (
            "contains semantic fact"
        ),
    }
    lines = [
        "digraph static_semantic_graph {",
        "  rankdir=LR;",
        '  graph [label="Static Semantic Containment", labelloc="t"];',
        '  node [fontname="sans-serif"];',
        '  edge [fontname="sans-serif"];',
    ]
    for node in projection.nodes:
        lines.append(
            f'  {node_names[node.id]} [shape={shapes[node.kind]}, '
            f'label="{escape_dot_string(_semantic_node_label(node))}"];'
        )
    for relation in projection.relations:
        lines.append(
            f"  {node_names[relation.source_node_id]} -> "
            f"{node_names[relation.target_node_id]} "
            f'[label="{relation_labels[relation.relation_kind]}"];'
        )
    lines.extend(("}", ""))
    return "\n".join(lines)


def render_static_program_structure_summary_markdown(
    inventory: StaticProgramStructureInventory,
) -> str:
    """Render one frozen partial function-local CFG inventory."""

    source = _detached_structure_inventory(inventory)
    block_count = sum(
        len(function.basic_block_addresses) for function in source.functions
    )
    edge_count = sum(
        len(function.directed_edges) for function in source.functions
    )
    zero_edge_count = sum(
        not function.directed_edges for function in source.functions
    )
    lines = [
        "# Static Program Structure Inventory",
        "",
        f"- Artifact ID: `{source.artifact_id}`",
        f"- Artifact SHA-256: `{source.artifact_sha256}`",
        f"- Architecture: `{source.architecture.value}`",
        f"- Instruction set: `{source.instruction_set}`",
        f"- Analyzer profile: `{source.analyzer_profile_id}`",
        f"- Inventory ID: `{source.id}`",
        f"- Inventory scope: `{source.analysis_scope.value}`",
        "",
        "## Counts",
        "",
        f"- Function count: {len(source.functions)}",
        f"- Basic-block count: {block_count}",
        f"- Directed CFG-edge count: {edge_count}",
        f"- Zero-edge function count: {zero_edge_count}",
        "",
        "## Functions",
        "",
    ]
    if not source.functions:
        lines.extend(
            (
                "No function CFGs recovered under this extractor profile.",
                "",
            )
        )
    for function in source.functions:
        name = function.function_name if function.function_name else "None"
        lines.extend(
            (
                f"### {_markdown_cell(name)} @ `{function.function_address}`",
                "",
                "Blocks:",
                "",
                *(f"- `{address}`" for address in function.basic_block_addresses),
                "",
                "Static CFG edges:",
                "",
            )
        )
        if function.directed_edges:
            lines.extend(
                f"- `{edge.source_basic_block_address}` -> "
                f"`{edge.target_basic_block_address}`"
                for edge in function.directed_edges
            )
            lines.append("")
        else:
            lines.extend(
                (
                    "No directed CFG edges recovered under this extractor profile.",
                    "",
                )
            )
    return "\n".join(lines)


def render_static_program_structure_graph_dot(
    inventory: StaticProgramStructureInventory,
) -> str:
    """Render function clusters and only exact frozen static CFG edges."""

    source = _detached_structure_inventory(inventory)
    lines = [
        "digraph static_program_structure {",
        "  rankdir=LR;",
        '  graph [label="Partial Function-Local Static CFG", labelloc="t"];',
        '  node [shape=ellipse, fontname="sans-serif"];',
        '  edge [fontname="sans-serif"];',
    ]
    block_names: dict[tuple[int, str], str] = {}
    for function_index, function in enumerate(source.functions):
        name = function.function_name if function.function_name else "None"
        lines.append(f"  subgraph cluster_{function_index} {{")
        lines.append(
            "    label=\""
            + escape_dot_string(
                f"Function\n{name}\n{function.function_address}"
            )
            + "\";"
        )
        for block_index, address in enumerate(
            function.basic_block_addresses
        ):
            node_name = f"block_{function_index}_{block_index}"
            block_names[(function_index, address)] = node_name
            lines.append(
                f'    {node_name} [label="Basic Block\\n'
                f'{escape_dot_string(address)}"];'
            )
        lines.append("  }")
    for function_index, function in enumerate(source.functions):
        for edge in function.directed_edges:
            source_name = block_names[
                (function_index, edge.source_basic_block_address)
            ]
            target_name = block_names[
                (function_index, edge.target_basic_block_address)
            ]
            lines.append(
                f"  {source_name} -> {target_name} "
                '[label="static CFG", color="navy"];'
            )
    lines.extend(("}", ""))
    return "\n".join(lines)


def _provenance_comparison(
    semantic: StaticSemanticInventory,
    structure: StaticProgramStructureInventory,
) -> list[tuple[str, str, str, bool]]:
    return [
        (
            "architecture",
            semantic.architecture.value,
            structure.architecture.value,
            semantic.architecture is structure.architecture,
        ),
        (
            "artifact_id",
            semantic.artifact_id,
            structure.artifact_id,
            semantic.artifact_id == structure.artifact_id,
        ),
        (
            "artifact_sha256",
            semantic.artifact_sha256,
            structure.artifact_sha256,
            semantic.artifact_sha256 == structure.artifact_sha256,
        ),
        (
            "instruction_set",
            semantic.instruction_set,
            structure.instruction_set,
            semantic.instruction_set == structure.instruction_set,
        ),
    ]


def render_static_analysis_inspection_summary_markdown(
    semantic_inventory: StaticSemanticInventory,
    semantic_graph_materialization: StaticSemanticGraphProjectionMaterialization,
    structure_inventory: StaticProgramStructureInventory,
) -> str:
    """Compare independent provenance and expose source-coverage differences."""

    semantic = _detached_semantic_inventory(semantic_inventory)
    graph = _detached_graph_materialization(
        semantic_graph_materialization
    )
    structure = _detached_structure_inventory(structure_inventory)
    if graph.source_inventory_snapshot != semantic:
        raise ValueError("semantic graph source snapshot does not match inventory")
    comparison = _provenance_comparison(semantic, structure)
    lines = [
        "# Static Analysis Inspection Summary",
        "",
        "## Independent sources",
        "",
        "### Semantic source",
        "",
        f"- Inventory ID: `{semantic.id}`",
        f"- Decoder profile: `{semantic.decoder_profile_id}`",
        "",
        "### Semantic graph",
        "",
        f"- Projection ID: `{graph.projection.id}`",
        f"- Materialization ID: `{graph.id}`",
        "",
        "### Structure source",
        "",
        f"- Inventory ID: `{structure.id}`",
        f"- Analyzer profile: `{structure.analyzer_profile_id}`",
        "",
        "## Independent source provenance comparison",
        "",
        "| Field | Semantic source | Structure source | Equal |",
        "|---|---|---|---|",
    ]
    for field, semantic_value, structure_value, equal in comparison:
        lines.append(
            f"| `{field}` | `{_markdown_cell(semantic_value)}` | "
            f"`{_markdown_cell(structure_value)}` | "
            f"`{str(equal).lower()}` |"
        )
    if not all(item[3] for item in comparison):
        lines.extend(
            (
                "",
                "## Cross-source structural coverage",
                "",
                "Cross-source structural coverage comparison was not "
                "performed because the independent source provenance does "
                "not match exactly.",
                "",
                "Presentation != fusion.",
                "",
                "Inspection summary != vulnerability verdict.",
                "",
            )
        )
        return "\n".join(lines)
    structure_functions = {
        function.function_address: function for function in structure.functions
    }
    differences: list[
        tuple[StaticSemanticInstructionFact, bool | None, bool | None]
    ] = []
    for fact in semantic.facts:
        function = (
            structure_functions.get(fact.function_address)
            if fact.function_address is not None
            else None
        )
        function_present = (
            function is not None
            if fact.function_address is not None
            else None
        )
        block_present = (
            bool(
                function is not None
                and fact.basic_block_address
                in function.basic_block_addresses
            )
            if fact.basic_block_address is not None
            else None
        )
        if function_present is not True or block_present is not True:
            differences.append((fact, function_present, block_present))
    lines.extend(
        [
            "",
            "## Semantic-only static provenance under current source profiles",
            "",
        ]
    )
    if not differences:
        lines.extend(("No source-coverage differences observed.", ""))
    for fact, function_present, block_present in differences:
        lines.extend(
            (
                f"### `{fact.operation.value}` at `{fact.instruction_address}`",
                "",
                f"- instruction_address = `{fact.instruction_address}`",
                f"- function_address = `{_markdown_cell(fact.function_address)}`",
                f"- basic_block_address = `{_markdown_cell(fact.basic_block_address)}`",
            )
        )
        if fact.function_address is None:
            lines.append("- semantic function provenance = `not provided`")
        else:
            lines.append(
                "- structure function "
                f"`{fact.function_address}` = "
                f"`{'present' if function_present else 'absent'}`"
            )
        if fact.basic_block_address is None:
            lines.extend(
                (
                    "- semantic basic-block provenance = `not provided`",
                    "",
                    "Semantic source provides no basic-block provenance for "
                    "this fact.",
                    "",
                    "Instruction Address != Basic-Block Provenance.",
                )
            )
        elif function_present:
            lines.append(
                f"- structure block `{fact.basic_block_address}` = "
                f"`{'present' if block_present else 'absent'}`"
            )
        else:
            lines.append(
                f"- structure block `{fact.basic_block_address}` = "
                "`not comparable`"
            )
        lines.append("")
        if function_present is False:
            lines.extend(
                (
                    "No function-level CFG support was independently "
                    "recovered under the structure source profile.",
                    "",
                )
            )
        elif block_present is False:
            lines.extend(
                (
                    "No exact basic-block support was independently recovered "
                    "under the structure source profile.",
                    "",
                )
            )
    lines.extend(
        (
            "Presentation != fusion.",
            "",
            "Inspection summary != vulnerability verdict.",
            "",
        )
    )
    return "\n".join(lines)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _manifest_text(
    *,
    semantic: StaticSemanticInventory,
    graph: StaticSemanticGraphProjectionMaterialization,
    structure: StaticProgramStructureInventory,
    outputs: dict[str, str],
) -> str:
    comparison = _provenance_comparison(semantic, structure)
    common = all(item[3] for item in comparison)
    manifest = {
        "architecture": semantic.architecture.value,
        "artifact_id": semantic.artifact_id,
        "artifact_sha256": semantic.artifact_sha256,
        "decoder_profile_id": semantic.decoder_profile_id,
        "files": {
            filename: {
                "byte_size": len(outputs[filename].encode("utf-8")),
                "sha256": _sha256_text(outputs[filename]),
            }
            for filename in _TEXT_FILENAMES
        },
        "independent_source_provenance_equal": common,
        "instruction_set": semantic.instruction_set,
        "semantic_graph_materialization_id": graph.id,
        "semantic_graph_projection_id": graph.projection.id,
        "semantic_inventory_id": semantic.id,
        "structure_analyzer_profile_id": structure.analyzer_profile_id,
        "structure_inventory_id": structure.id,
    }
    return _canonical_json(manifest)


def render_dot_to_svg_if_available(
    dot_source: str,
    output_path: Path,
) -> bool:
    """Render DOT with a local Graphviz executable when available."""

    executable = shutil.which("dot")
    if executable is None:
        return False
    try:
        completed = subprocess.run(
            [executable, "-Tsvg"],
            input=dot_source.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
        )
    except OSError:
        return False
    if completed.returncode != 0:
        return False
    output_path.write_bytes(completed.stdout)
    return True


def export_static_analysis_artifact_bundle(
    *,
    semantic_inventory: StaticSemanticInventory,
    semantic_graph_materialization: StaticSemanticGraphProjectionMaterialization,
    structure_inventory: StaticProgramStructureInventory,
    output_directory: Path,
    include_svg: bool = True,
) -> StaticAnalysisArtifactBundleResult:
    """Write one deterministic inspection bundle with fixed filenames."""

    semantic = _detached_semantic_inventory(semantic_inventory)
    graph = _detached_graph_materialization(
        semantic_graph_materialization
    )
    structure = _detached_structure_inventory(structure_inventory)
    if graph.source_inventory_snapshot != semantic:
        raise ValueError("semantic graph source snapshot does not match inventory")
    outputs = {
        "semantic_inventory.json": render_static_semantic_inventory_json(
            semantic
        ),
        "semantic_graph.json": render_static_semantic_graph_json(graph),
        "semantic_summary.md": render_static_semantic_summary_markdown(
            semantic, graph
        ),
        "semantic_graph.dot": render_static_semantic_graph_dot(graph),
        "structure_inventory.json": (
            render_static_program_structure_inventory_json(structure)
        ),
        "structure_summary.md": (
            render_static_program_structure_summary_markdown(structure)
        ),
        "structure_graph.dot": (
            render_static_program_structure_graph_dot(structure)
        ),
        "inspection_summary.md": (
            render_static_analysis_inspection_summary_markdown(
                semantic, graph, structure
            )
        ),
    }
    output_directory.mkdir(parents=True, exist_ok=True)
    for filename in _TEXT_FILENAMES:
        (output_directory / filename).write_text(
            outputs[filename], encoding="utf-8"
        )
    manifest = _manifest_text(
        semantic=semantic,
        graph=graph,
        structure=structure,
        outputs=outputs,
    )
    (output_directory / "manifest.json").write_text(
        manifest, encoding="utf-8"
    )
    svg_files: list[str] = []
    if include_svg:
        for dot_filename, svg_filename in (
            ("semantic_graph.dot", "semantic_graph.svg"),
            ("structure_graph.dot", "structure_graph.svg"),
        ):
            if render_dot_to_svg_if_available(
                outputs[dot_filename], output_directory / svg_filename
            ):
                svg_files.append(svg_filename)
    return StaticAnalysisArtifactBundleResult(
        files=(*_TEXT_FILENAMES, "manifest.json"),
        svg_files=tuple(svg_files),
    )
