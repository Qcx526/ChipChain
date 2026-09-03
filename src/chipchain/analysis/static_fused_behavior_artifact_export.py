"""Deterministic presentation of fused static behavior materializations."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from chipchain.analysis.static_analysis_artifact_export import (
    escape_dot_string,
    render_dot_to_svg_if_available,
)
from chipchain.analysis.static_fused_behavior_fusion import (
    StaticFusedBehaviorGraphMaterialization,
)
from chipchain.analysis.static_fused_behavior_models import (
    StaticFusedBehaviorNode,
    StaticFusedBehaviorNodeKind,
    StaticFusedBehaviorRelationKind,
)


_TEXT_FILENAMES = (
    "fused_graph.json",
    "fused_summary.md",
    "fused_graph.dot",
)


@dataclass(frozen=True)
class StaticFusedBehaviorArtifactBundleResult:
    """Names of files written by one fused static presentation export."""

    files: tuple[str, ...]
    svg_files: tuple[str, ...]


def _detached_materialization(
    materialization: StaticFusedBehaviorGraphMaterialization,
) -> StaticFusedBehaviorGraphMaterialization:
    return StaticFusedBehaviorGraphMaterialization.model_validate(
        materialization.model_dump(mode="json")
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ) + "\n"


def _source_support(node: StaticFusedBehaviorNode) -> str:
    semantic = bool(node.semantic_source_node_ids)
    structure = bool(node.structure_function_cfg_ids)
    if semantic and structure:
        return "semantic+structure"
    if semantic:
        return "semantic"
    return "structure"


def _attribute_text(node: StaticFusedBehaviorNode) -> str:
    if not node.attributes:
        return ""
    return "; ".join(
        f"{attribute.name.value}={attribute.value}"
        for attribute in node.attributes
    )


def render_static_fused_behavior_graph_json(
    materialization: StaticFusedBehaviorGraphMaterialization,
) -> str:
    """Render the exact standalone fused materialization as canonical JSON."""

    source = _detached_materialization(materialization)
    return _canonical_json(source.model_dump(mode="json"))


def render_static_fused_behavior_summary_markdown(
    materialization: StaticFusedBehaviorGraphMaterialization,
) -> str:
    """Render exact fused nodes and relations for human inspection."""

    source = _detached_materialization(materialization)
    projection = source.projection
    node_counts = Counter(node.kind for node in projection.nodes)
    relation_counts = Counter(
        relation.relation_kind for relation in projection.relations
    )
    node_by_id = {node.id: node for node in projection.nodes}
    membership = [
        relation
        for relation in projection.relations
        if relation.relation_kind
        is StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK
    ]
    block_facts: dict[str, list[StaticFusedBehaviorNode]] = {}
    function_facts: dict[str, list[StaticFusedBehaviorNode]] = {}
    successors: dict[str, list[StaticFusedBehaviorNode]] = {}
    for relation in projection.relations:
        if relation.relation_kind is (
            StaticFusedBehaviorRelationKind
            .BASIC_BLOCK_CONTAINS_SEMANTIC_FACT
        ):
            block_facts.setdefault(relation.source_node_id, []).append(
                node_by_id[relation.target_node_id]
            )
        elif relation.relation_kind is (
            StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT
        ):
            function_facts.setdefault(relation.source_node_id, []).append(
                node_by_id[relation.target_node_id]
            )
        elif relation.relation_kind is (
            StaticFusedBehaviorRelationKind.CFG_SUCCESSOR
        ):
            successors.setdefault(relation.source_node_id, []).append(
                node_by_id[relation.target_node_id]
            )

    lines = [
        "# Static Fused Behavior Graph",
        "",
        f"- Architecture: `{projection.architecture.value}`",
        f"- Artifact ID: `{projection.artifact_id}`",
        f"- Artifact SHA-256: `{projection.artifact_sha256}`",
        f"- Instruction set: `{projection.instruction_set}`",
        f"- Semantic inventory ID: `{projection.semantic_inventory_id}`",
        "- Semantic graph materialization ID: "
        f"`{projection.semantic_graph_materialization_id}`",
        f"- Structure inventory ID: `{projection.structure_inventory_id}`",
        f"- Fused projection ID: `{projection.id}`",
        f"- Fused materialization ID: `{source.id}`",
        "",
        "## Counts",
        "",
        "- Function count: "
        f"{node_counts[StaticFusedBehaviorNodeKind.FUNCTION]}",
        "- Basic-block count: "
        f"{node_counts[StaticFusedBehaviorNodeKind.BASIC_BLOCK]}",
        "- Semantic-fact count: "
        f"{node_counts[StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT]}",
        "- CFG successor count: "
        f"{relation_counts[StaticFusedBehaviorRelationKind.CFG_SUCCESSOR]}",
        "",
        "## Function / Block / Semantic Fact / Static CFG",
        "",
        "| Function | Block | Source support | Semantic facts in block | "
        "Static CFG successors |",
        "|---|---|---|---|---|",
    ]
    for relation in membership:
        function = node_by_id[relation.source_node_id]
        block = node_by_id[relation.target_node_id]
        facts = sorted(
            block_facts.get(block.id, []),
            key=lambda item: (int(item.instruction_address or "0x0", 16), item.id),
        )
        fact_text = ", ".join(
            f"{fact.operation.value} @ {fact.instruction_address}"
            for fact in facts
        ) or "None"
        targets = sorted(
            successors.get(block.id, []),
            key=lambda item: (int(item.basic_block_address or "0x0", 16), item.id),
        )
        successor_text = ", ".join(
            target.basic_block_address or "None" for target in targets
        ) or "None"
        lines.append(
            f"| {function.function_name or 'None'} @ "
            f"{function.function_address} | {block.basic_block_address} | "
            f"{_source_support(block)} | {fact_text} | {successor_text} |"
        )
    lines.extend(("", "## Function-contained semantic facts", ""))
    direct_fact_count = 0
    for function_id, facts in sorted(function_facts.items()):
        function = node_by_id[function_id]
        for fact in sorted(
            facts,
            key=lambda item: (int(item.instruction_address or "0x0", 16), item.id),
        ):
            lines.append(
                f"- `{function.function_address}` -> "
                f"`{fact.operation.value}` at `{fact.instruction_address}`"
            )
            direct_fact_count += 1
    if not direct_fact_count:
        lines.append("None.")
    lines.extend(
        (
            "",
            "Static Fact != Runtime Execution.",
            "",
            "CFG_SUCCESSOR != Runtime Execution.",
            "",
            "CFG Reachability != Runtime Reachability.",
            "",
            "CFG Reachability != Symbolic Feasibility.",
            "",
            "CFG Reachability != Causality.",
            "",
            "Fusion != Verification.",
            "",
            "Fusion != Vulnerability.",
            "",
            "Instruction Address != Basic-Block Provenance.",
            "",
        )
    )
    return "\n".join(lines)


def _node_label(node: StaticFusedBehaviorNode) -> str:
    support = _source_support(node)
    if node.kind is StaticFusedBehaviorNodeKind.FUNCTION:
        return (
            f"Function\n{node.function_name or 'None'}\n"
            f"{node.function_address}\n[source: {support}]"
        )
    if node.kind is StaticFusedBehaviorNodeKind.BASIC_BLOCK:
        scope = (
            node.function_address
            if node.function_address is not None
            else "unscoped"
        )
        return (
            f"Basic Block\n{node.basic_block_address}\n"
            f"[function: {scope}]\n[source: {support}]"
        )
    attributes = _attribute_text(node)
    suffix = f"\n{attributes}" if attributes else ""
    return (
        f"{node.operation.value}\n{node.instruction_address}"
        f"\n[source: semantic]{suffix}"
    )


def render_static_fused_behavior_graph_dot(
    materialization: StaticFusedBehaviorGraphMaterialization,
) -> str:
    """Render only exact fused nodes and relations as Graphviz DOT."""

    source = _detached_materialization(materialization)
    projection = source.projection
    names = {
        node.id: f"node_{index}"
        for index, node in enumerate(projection.nodes)
    }
    shapes = {
        StaticFusedBehaviorNodeKind.FUNCTION: "box",
        StaticFusedBehaviorNodeKind.BASIC_BLOCK: "ellipse",
        StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT: "note",
    }
    lines = [
        "digraph static_fused_behavior {",
        "  rankdir=LR;",
        '  graph [label="Provenance-Bound Static Fused Behavior", labelloc="t"];',
        '  node [fontname="sans-serif"];',
        '  edge [fontname="sans-serif"];',
    ]
    for node in projection.nodes:
        lines.append(
            f"  {names[node.id]} [shape={shapes[node.kind]}, "
            f'label="{escape_dot_string(_node_label(node))}"];'
        )
    for relation in projection.relations:
        if relation.relation_kind is StaticFusedBehaviorRelationKind.CFG_SUCCESSOR:
            attributes = 'label="static CFG", color="navy", penwidth=2'
        elif relation.relation_kind is (
            StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK
        ):
            attributes = 'label="contains block"'
        else:
            attributes = 'label="contains semantic fact"'
        lines.append(
            f"  {names[relation.source_node_id]} -> "
            f"{names[relation.target_node_id]} [{attributes}];"
        )
    lines.extend(("}", ""))
    return "\n".join(lines)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _manifest_text(
    materialization: StaticFusedBehaviorGraphMaterialization,
    outputs: dict[str, str],
) -> str:
    projection = materialization.projection
    return _canonical_json(
        {
            "architecture": projection.architecture.value,
            "artifact_id": projection.artifact_id,
            "artifact_sha256": projection.artifact_sha256,
            "files": {
                filename: {
                    "byte_size": len(outputs[filename].encode("utf-8")),
                    "sha256": _sha256_text(outputs[filename]),
                }
                for filename in _TEXT_FILENAMES
            },
            "fused_materialization_id": materialization.id,
            "fused_projection_id": projection.id,
            "instruction_set": projection.instruction_set,
            "semantic_graph_materialization_id": (
                projection.semantic_graph_materialization_id
            ),
            "semantic_inventory_id": projection.semantic_inventory_id,
            "structure_inventory_id": projection.structure_inventory_id,
        }
    )


def export_static_fused_behavior_artifact_bundle(
    *,
    materialization: StaticFusedBehaviorGraphMaterialization,
    output_directory: Path,
    include_svg: bool = True,
) -> StaticFusedBehaviorArtifactBundleResult:
    """Write one deterministic fused static inspection bundle."""

    source = _detached_materialization(materialization)
    outputs = {
        "fused_graph.json": render_static_fused_behavior_graph_json(source),
        "fused_summary.md": render_static_fused_behavior_summary_markdown(
            source
        ),
        "fused_graph.dot": render_static_fused_behavior_graph_dot(source),
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
        outputs["fused_graph.dot"], output_directory / "fused_graph.svg"
    ):
        svg_files.append("fused_graph.svg")
    return StaticFusedBehaviorArtifactBundleResult(
        files=(*_TEXT_FILENAMES, "manifest.json"),
        svg_files=tuple(svg_files),
    )
