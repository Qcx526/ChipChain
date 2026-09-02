"""Pure projection from static semantic inventory to its source graph."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import model_validator

from chipchain.analysis.static_semantic_graph_models import (
    PHASE10D_STATIC_SEMANTIC_GRAPH_MATERIALIZATION_CONTRACT,
    StaticSemanticGraphNode,
    StaticSemanticGraphNodeKind,
    StaticSemanticGraphProjection,
    StaticSemanticGraphProjectionScope,
    StaticSemanticGraphRelation,
    StaticSemanticGraphRelationKind,
    static_semantic_graph_diagnostics,
)
from chipchain.analysis.static_semantic_models import StaticSemanticInventory
from chipchain.models.common import DomainModel, Identifier


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def static_semantic_graph_materialization_id(payload: object) -> str:
    """Return the deterministic source-plus-projection identity."""

    digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return f"static-semantic-graph-materialization:{digest}"


def _node_values(inventory: StaticSemanticInventory) -> dict[str, object]:
    return {
        "architecture": inventory.architecture,
        "artifact_id": inventory.artifact_id,
        "artifact_sha256": inventory.artifact_sha256,
        "source_inventory_id": inventory.id,
    }


def _relation_values(inventory: StaticSemanticInventory) -> dict[str, object]:
    return _node_values(inventory)


def _project_snapshot(
    inventory: StaticSemanticInventory,
) -> StaticSemanticGraphProjection:
    function_support: dict[str, set[str]] = {}
    function_names: dict[str, set[str]] = {}
    block_support: dict[tuple[str | None, str], set[str]] = {}
    for fact in inventory.facts:
        if fact.function_address is not None:
            function_support.setdefault(fact.function_address, set()).add(fact.id)
            if fact.function_name is not None:
                function_names.setdefault(fact.function_address, set()).add(
                    fact.function_name
                )
        if fact.basic_block_address is not None:
            block_support.setdefault(
                (fact.function_address, fact.basic_block_address), set()
            ).add(fact.id)

    resolved_function_names: dict[str, str | None] = {}
    for address in sorted(function_support, key=lambda value: int(value, 16)):
        names = function_names.get(address, set())
        if len(names) > 1:
            raise ValueError("conflicting function names share one address")
        resolved_function_names[address] = next(iter(names), None)

    common_node = _node_values(inventory)
    function_nodes = {
        address: StaticSemanticGraphNode.create(
            kind=StaticSemanticGraphNodeKind.FUNCTION,
            **common_node,
            source_fact_ids=sorted(function_support[address]),
            function_address=address,
            function_name=resolved_function_names[address],
        )
        for address in sorted(function_support, key=lambda value: int(value, 16))
    }
    block_nodes = {
        key: StaticSemanticGraphNode.create(
            kind=StaticSemanticGraphNodeKind.BASIC_BLOCK,
            **common_node,
            source_fact_ids=sorted(block_support[key]),
            function_address=key[0],
            function_name=(
                resolved_function_names[key[0]] if key[0] is not None else None
            ),
            basic_block_address=key[1],
        )
        for key in sorted(
            block_support,
            key=lambda item: (
                item[0] is None,
                int(item[0] or "0x0", 16),
                int(item[1], 16),
            ),
        )
    }
    fact_nodes = {
        fact.id: StaticSemanticGraphNode.create(
            kind=StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT,
            **common_node,
            source_fact_ids=[fact.id],
            function_address=fact.function_address,
            function_name=fact.function_name,
            basic_block_address=fact.basic_block_address,
            instruction_address=fact.instruction_address,
            instruction_bytes=fact.instruction_bytes,
            instruction_size=fact.instruction_size,
            operation=fact.operation,
            attributes=fact.attributes,
            fact_scope=fact.fact_scope,
        )
        for fact in inventory.facts
    }

    relations: list[StaticSemanticGraphRelation] = []
    common_relation = _relation_values(inventory)
    for key, block in block_nodes.items():
        function_address, _ = key
        if function_address is None:
            continue
        relations.append(
            StaticSemanticGraphRelation.create(
                relation_kind=(
                    StaticSemanticGraphRelationKind
                    .FUNCTION_CONTAINS_BASIC_BLOCK
                ),
                **common_relation,
                source_node_id=function_nodes[function_address].id,
                target_node_id=block.id,
                source_fact_ids=block.source_fact_ids,
            )
        )
    for fact in inventory.facts:
        fact_node = fact_nodes[fact.id]
        if fact.basic_block_address is not None:
            block = block_nodes[
                (fact.function_address, fact.basic_block_address)
            ]
            relations.append(
                StaticSemanticGraphRelation.create(
                    relation_kind=(
                        StaticSemanticGraphRelationKind
                        .BASIC_BLOCK_CONTAINS_SEMANTIC_FACT
                    ),
                    **common_relation,
                    source_node_id=block.id,
                    target_node_id=fact_node.id,
                    source_fact_ids=[fact.id],
                )
            )
        elif fact.function_address is not None:
            relations.append(
                StaticSemanticGraphRelation.create(
                    relation_kind=(
                        StaticSemanticGraphRelationKind
                        .FUNCTION_CONTAINS_SEMANTIC_FACT
                    ),
                    **common_relation,
                    source_node_id=function_nodes[fact.function_address].id,
                    target_node_id=fact_node.id,
                    source_fact_ids=[fact.id],
                )
            )

    nodes = [*function_nodes.values(), *block_nodes.values(), *fact_nodes.values()]
    return StaticSemanticGraphProjection.create(
        architecture=inventory.architecture,
        artifact_id=inventory.artifact_id,
        artifact_sha256=inventory.artifact_sha256,
        source_inventory_id=inventory.id,
        source_inventory_contract=inventory.contract,
        decoder_profile_id=inventory.decoder_profile_id,
        instruction_set=inventory.instruction_set,
        source_inventory_scope=inventory.analysis_scope,
        nodes=nodes,
        relations=relations,
        projection_scope=(
            StaticSemanticGraphProjectionScope
            .PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY_GRAPH
        ),
        diagnostic_codes=static_semantic_graph_diagnostics(nodes, relations),
    )


class _StaticSemanticGraphProjectionMaterializationBody(DomainModel):
    contract: Literal[
        "phase10d_static_semantic_graph_materialization_v1"
    ]
    source_inventory_id: Identifier
    source_inventory_snapshot: StaticSemanticInventory
    projection: StaticSemanticGraphProjection

    @model_validator(mode="after")
    def validate_standalone_integrity(
        self,
    ) -> "_StaticSemanticGraphProjectionMaterializationBody":
        source = StaticSemanticInventory.model_validate(
            self.source_inventory_snapshot.model_dump(mode="json")
        )
        projection = StaticSemanticGraphProjection.model_validate(
            self.projection.model_dump(mode="json")
        )
        if self.source_inventory_id != source.id:
            raise ValueError("semantic graph materialization source ID mismatch")
        expected_binding = (
            source.architecture,
            source.artifact_id,
            source.artifact_sha256,
            source.id,
            source.contract,
            source.decoder_profile_id,
            source.instruction_set,
            source.analysis_scope,
        )
        if (
            projection.architecture,
            projection.artifact_id,
            projection.artifact_sha256,
            projection.source_inventory_id,
            projection.source_inventory_contract,
            projection.decoder_profile_id,
            projection.instruction_set,
            projection.source_inventory_scope,
        ) != expected_binding:
            raise ValueError("semantic graph materialization binding mismatch")
        if projection != _project_snapshot(source):
            raise ValueError(
                "semantic graph projection differs from deterministic reprojection"
            )
        return self


class StaticSemanticGraphProjectionMaterialization(
    _StaticSemanticGraphProjectionMaterializationBody
):
    """Detached inventory snapshot plus its deterministic graph projection."""

    id: Identifier

    @classmethod
    def create(
        cls, *, source_inventory: StaticSemanticInventory
    ) -> "StaticSemanticGraphProjectionMaterialization":
        source = StaticSemanticInventory.model_validate(
            source_inventory.model_dump(mode="json")
        )
        values = {
            "contract": (
                PHASE10D_STATIC_SEMANTIC_GRAPH_MATERIALIZATION_CONTRACT
            ),
            "source_inventory_id": source.id,
            "source_inventory_snapshot": source,
            "projection": _project_snapshot(source),
        }
        body = (
            _StaticSemanticGraphProjectionMaterializationBody.model_validate(
                values
            )
        )
        payload = body.model_dump(mode="json")
        return cls(
            id=static_semantic_graph_materialization_id(payload), **payload
        )

    @model_validator(mode="after")
    def validate_deterministic_id(
        self,
    ) -> "StaticSemanticGraphProjectionMaterialization":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_semantic_graph_materialization_id(payload):
            raise ValueError("static semantic graph materialization ID mismatch")
        return self


def project_static_semantic_inventory(
    inventory: StaticSemanticInventory,
) -> StaticSemanticGraphProjectionMaterialization:
    """Project one detached inventory without filesystem or backend access."""

    return StaticSemanticGraphProjectionMaterialization.create(
        source_inventory=inventory
    )
