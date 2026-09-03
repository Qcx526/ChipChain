"""Pure fusion of frozen semantic-graph and program-structure sources."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Literal

from pydantic import model_validator

from chipchain.analysis.static_fused_behavior_models import (
    StaticFusedBehaviorGraphProjection,
    StaticFusedBehaviorNode,
    StaticFusedBehaviorNodeKind,
    StaticFusedBehaviorRelation,
    StaticFusedBehaviorRelationKind,
)
from chipchain.analysis.static_program_structure_models import (
    StaticProgramCfgSemantics,
    StaticProgramStructureInventory,
    static_program_basic_block_source_id,
)
from chipchain.analysis.static_semantic_graph_models import (
    StaticSemanticGraphNode,
    StaticSemanticGraphNodeKind,
    StaticSemanticGraphRelationKind,
)
from chipchain.analysis.static_semantic_graph_projection import (
    StaticSemanticGraphProjectionMaterialization,
)
from chipchain.models.common import DomainModel, Identifier


PHASE10D_STATIC_FUSED_BEHAVIOR_GRAPH_MATERIALIZATION_CONTRACT = (
    "phase10d_static_fused_behavior_graph_materialization_v1"
)


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def static_fused_behavior_graph_materialization_id(payload: object) -> str:
    """Return the deterministic identity of one exact fusion materialization."""

    digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return f"static-fused-behavior-graph-materialization:{digest}"


def _detached_sources(
    semantic_graph_materialization: (
        StaticSemanticGraphProjectionMaterialization
    ),
    structure_inventory: StaticProgramStructureInventory,
) -> tuple[
    StaticSemanticGraphProjectionMaterialization,
    StaticProgramStructureInventory,
]:
    semantic = StaticSemanticGraphProjectionMaterialization.model_validate(
        semantic_graph_materialization.model_dump(mode="json")
    )
    structure = StaticProgramStructureInventory.model_validate(
        structure_inventory.model_dump(mode="json")
    )
    projection = semantic.projection
    if (
        projection.architecture,
        projection.artifact_id,
        projection.artifact_sha256,
        projection.instruction_set,
    ) != (
        structure.architecture,
        structure.artifact_id,
        structure.artifact_sha256,
        structure.instruction_set,
    ):
        raise ValueError("static fusion source provenance does not match exactly")
    return semantic, structure


def _resolve_function_name(
    semantic_node: StaticSemanticGraphNode | None,
    structure_name: str | None,
) -> str | None:
    names = {
        name
        for name in (
            semantic_node.function_name if semantic_node else None,
            structure_name,
        )
        if name is not None
    }
    if len(names) > 1:
        raise ValueError("static fusion function names conflict")
    return next(iter(names), None)


@dataclass
class _RelationSupport:
    semantic_relation_ids: set[str] = field(default_factory=set)
    structure_function_cfg_ids: set[str] = field(default_factory=set)
    structure_block_source_ids: set[str] = field(default_factory=set)
    structure_cfg_edge_ids: set[str] = field(default_factory=set)
    cfg_semantics: StaticProgramCfgSemantics | None = None


def _fuse_projection(
    semantic: StaticSemanticGraphProjectionMaterialization,
    structure: StaticProgramStructureInventory,
) -> StaticFusedBehaviorGraphProjection:
    semantic_projection = semantic.projection
    common = {
        "architecture": semantic_projection.architecture,
        "artifact_id": semantic_projection.artifact_id,
        "artifact_sha256": semantic_projection.artifact_sha256,
        "instruction_set": semantic_projection.instruction_set,
    }
    semantic_functions = {
        node.function_address: node
        for node in semantic_projection.nodes
        if node.kind is StaticSemanticGraphNodeKind.FUNCTION
    }
    structure_functions = {
        function.function_address: function
        for function in structure.functions
    }
    function_addresses = sorted(
        set(semantic_functions) | set(structure_functions),
        key=lambda value: int(value, 16),
    )
    fused_functions: dict[str, StaticFusedBehaviorNode] = {}
    semantic_node_to_fused: dict[str, StaticFusedBehaviorNode] = {}
    for address in function_addresses:
        semantic_node = semantic_functions.get(address)
        structure_function = structure_functions.get(address)
        function_name = _resolve_function_name(
            semantic_node,
            structure_function.function_name if structure_function else None,
        )
        fused = StaticFusedBehaviorNode.create(
            kind=StaticFusedBehaviorNodeKind.FUNCTION,
            **common,
            function_address=address,
            function_name=function_name,
            semantic_source_node_ids=(
                [semantic_node.id] if semantic_node else []
            ),
            semantic_source_fact_ids=(
                semantic_node.source_fact_ids if semantic_node else []
            ),
            structure_function_cfg_ids=(
                [structure_function.id] if structure_function else []
            ),
        )
        fused_functions[address] = fused
        if semantic_node:
            semantic_node_to_fused[semantic_node.id] = fused

    semantic_blocks = {
        (node.function_address, node.basic_block_address): node
        for node in semantic_projection.nodes
        if node.kind is StaticSemanticGraphNodeKind.BASIC_BLOCK
    }
    structure_blocks: dict[tuple[str, str], tuple[str, str]] = {}
    for function in structure.functions:
        for block_address in function.basic_block_addresses:
            structure_blocks[(function.function_address, block_address)] = (
                function.id,
                static_program_basic_block_source_id(
                    function.id, block_address
                ),
            )
    block_keys = sorted(
        set(semantic_blocks) | set(structure_blocks),
        key=lambda item: (
            item[0] is None,
            int(item[0] or "0x0", 16),
            int(item[1], 16),
        ),
    )
    fused_blocks: dict[
        tuple[str | None, str], StaticFusedBehaviorNode
    ] = {}
    for key in block_keys:
        function_address, block_address = key
        semantic_node = semantic_blocks.get(key)
        structure_sources = structure_blocks.get(key)
        fused = StaticFusedBehaviorNode.create(
            kind=StaticFusedBehaviorNodeKind.BASIC_BLOCK,
            **common,
            function_address=function_address,
            function_name=(
                fused_functions[function_address].function_name
                if function_address is not None
                else None
            ),
            basic_block_address=block_address,
            semantic_source_node_ids=(
                [semantic_node.id] if semantic_node else []
            ),
            semantic_source_fact_ids=(
                semantic_node.source_fact_ids if semantic_node else []
            ),
            structure_function_cfg_ids=(
                [structure_sources[0]] if structure_sources else []
            ),
            structure_basic_block_source_ids=(
                [structure_sources[1]] if structure_sources else []
            ),
        )
        fused_blocks[key] = fused
        if semantic_node:
            semantic_node_to_fused[semantic_node.id] = fused

    fused_facts: list[StaticFusedBehaviorNode] = []
    for semantic_node in semantic_projection.nodes:
        if semantic_node.kind is not (
            StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT
        ):
            continue
        fused = StaticFusedBehaviorNode.create(
            kind=StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT,
            **common,
            function_address=semantic_node.function_address,
            function_name=semantic_node.function_name,
            basic_block_address=semantic_node.basic_block_address,
            instruction_address=semantic_node.instruction_address,
            instruction_bytes=semantic_node.instruction_bytes,
            instruction_size=semantic_node.instruction_size,
            operation=semantic_node.operation,
            attributes=semantic_node.attributes,
            fact_scope=semantic_node.fact_scope,
            semantic_source_node_ids=[semantic_node.id],
            semantic_source_fact_ids=semantic_node.source_fact_ids,
        )
        fused_facts.append(fused)
        semantic_node_to_fused[semantic_node.id] = fused

    relation_support: dict[
        tuple[StaticFusedBehaviorRelationKind, str, str], _RelationSupport
    ] = {}

    def support_for(
        kind: StaticFusedBehaviorRelationKind,
        source_id: str,
        target_id: str,
    ) -> _RelationSupport:
        return relation_support.setdefault(
            (kind, source_id, target_id), _RelationSupport()
        )

    semantic_relation_kinds = {
        StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK: (
            StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK
        ),
        StaticSemanticGraphRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT: (
            StaticFusedBehaviorRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT
        ),
        StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT: (
            StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT
        ),
    }
    for relation in semantic_projection.relations:
        fused_source = semantic_node_to_fused[relation.source_node_id]
        fused_target = semantic_node_to_fused[relation.target_node_id]
        support_for(
            semantic_relation_kinds[relation.relation_kind],
            fused_source.id,
            fused_target.id,
        ).semantic_relation_ids.add(relation.id)

    for function in structure.functions:
        fused_function = fused_functions[function.function_address]
        for block_address in function.basic_block_addresses:
            block = fused_blocks[(function.function_address, block_address)]
            block_source_id = static_program_basic_block_source_id(
                function.id, block_address
            )
            membership = support_for(
                StaticFusedBehaviorRelationKind
                .FUNCTION_CONTAINS_BASIC_BLOCK,
                fused_function.id,
                block.id,
            )
            membership.structure_function_cfg_ids.add(function.id)
            membership.structure_block_source_ids.add(block_source_id)
        for edge in function.directed_edges:
            source = fused_blocks[
                (function.function_address, edge.source_basic_block_address)
            ]
            target = fused_blocks[
                (function.function_address, edge.target_basic_block_address)
            ]
            cfg = support_for(
                StaticFusedBehaviorRelationKind.CFG_SUCCESSOR,
                source.id,
                target.id,
            )
            cfg.structure_function_cfg_ids.add(function.id)
            cfg.structure_block_source_ids.update(
                {
                    static_program_basic_block_source_id(
                        function.id, edge.source_basic_block_address
                    ),
                    static_program_basic_block_source_id(
                        function.id, edge.target_basic_block_address
                    ),
                }
            )
            cfg.structure_cfg_edge_ids.add(edge.id)
            cfg.cfg_semantics = edge.cfg_semantics

    relations = [
        StaticFusedBehaviorRelation.create(
            relation_kind=kind,
            **common,
            source_node_id=source_id,
            target_node_id=target_id,
            semantic_source_relation_ids=sorted(
                support.semantic_relation_ids
            ),
            structure_function_cfg_ids=sorted(
                support.structure_function_cfg_ids
            ),
            structure_basic_block_source_ids=sorted(
                support.structure_block_source_ids
            ),
            structure_cfg_edge_ids=sorted(
                support.structure_cfg_edge_ids
            ),
            cfg_semantics=support.cfg_semantics,
        )
        for (kind, source_id, target_id), support in relation_support.items()
    ]
    nodes = [
        *fused_functions.values(),
        *fused_blocks.values(),
        *fused_facts,
    ]
    return StaticFusedBehaviorGraphProjection.create(
        **common,
        semantic_inventory_id=semantic_projection.source_inventory_id,
        semantic_graph_projection_id=semantic_projection.id,
        semantic_graph_materialization_id=semantic.id,
        decoder_profile_id=semantic_projection.decoder_profile_id,
        semantic_source_scope=semantic_projection.source_inventory_scope,
        structure_inventory_id=structure.id,
        structure_analyzer_profile_id=structure.analyzer_profile_id,
        structure_source_scope=structure.analysis_scope,
        nodes=nodes,
        relations=relations,
    )


class _StaticFusedBehaviorGraphMaterializationBody(DomainModel):
    contract: Literal[
        "phase10d_static_fused_behavior_graph_materialization_v1"
    ]
    source_semantic_graph_materialization_id: Identifier
    source_semantic_graph_materialization: (
        StaticSemanticGraphProjectionMaterialization
    )
    source_structure_inventory_id: Identifier
    source_structure_inventory_snapshot: StaticProgramStructureInventory
    projection: StaticFusedBehaviorGraphProjection

    @model_validator(mode="after")
    def validate_standalone_integrity(
        self,
    ) -> "_StaticFusedBehaviorGraphMaterializationBody":
        semantic, structure = _detached_sources(
            self.source_semantic_graph_materialization,
            self.source_structure_inventory_snapshot,
        )
        projection = StaticFusedBehaviorGraphProjection.model_validate(
            self.projection.model_dump(mode="json")
        )
        if self.source_semantic_graph_materialization_id != semantic.id:
            raise ValueError("fused materialization semantic source ID mismatch")
        if self.source_structure_inventory_id != structure.id:
            raise ValueError("fused materialization structure source ID mismatch")
        if projection != _fuse_projection(semantic, structure):
            raise ValueError(
                "fused projection differs from deterministic reprojection"
            )
        return self


class StaticFusedBehaviorGraphMaterialization(
    _StaticFusedBehaviorGraphMaterializationBody
):
    """Detached source snapshots plus their deterministic fused projection."""

    id: Identifier

    @classmethod
    def create(
        cls,
        *,
        semantic_graph_materialization: (
            StaticSemanticGraphProjectionMaterialization
        ),
        structure_inventory: StaticProgramStructureInventory,
    ) -> "StaticFusedBehaviorGraphMaterialization":
        semantic, structure = _detached_sources(
            semantic_graph_materialization, structure_inventory
        )
        values = {
            "contract": (
                PHASE10D_STATIC_FUSED_BEHAVIOR_GRAPH_MATERIALIZATION_CONTRACT
            ),
            "source_semantic_graph_materialization_id": semantic.id,
            "source_semantic_graph_materialization": semantic,
            "source_structure_inventory_id": structure.id,
            "source_structure_inventory_snapshot": structure,
            "projection": _fuse_projection(semantic, structure),
        }
        body = _StaticFusedBehaviorGraphMaterializationBody.model_validate(
            values
        )
        payload = body.model_dump(mode="json")
        return cls(
            id=static_fused_behavior_graph_materialization_id(payload),
            **payload,
        )

    @model_validator(mode="after")
    def validate_deterministic_id(
        self,
    ) -> "StaticFusedBehaviorGraphMaterialization":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_fused_behavior_graph_materialization_id(payload):
            raise ValueError("static fused behavior materialization ID mismatch")
        return self


def fuse_static_semantic_and_program_structure(
    semantic_graph_materialization: (
        StaticSemanticGraphProjectionMaterialization
    ),
    structure_inventory: StaticProgramStructureInventory,
) -> StaticFusedBehaviorGraphMaterialization:
    """Fuse two exact detached static sources without backend access."""

    return StaticFusedBehaviorGraphMaterialization.create(
        semantic_graph_materialization=semantic_graph_materialization,
        structure_inventory=structure_inventory,
    )
