"""Architecture-neutral graph contracts for static semantic inventories."""

from __future__ import annotations

from enum import Enum
import hashlib
import json
import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.analysis.static_semantic_models import (
    PHASE10D_STATIC_SEMANTIC_INVENTORY_CONTRACT,
    StaticSemanticAttribute,
    StaticSemanticFactScope,
    StaticSemanticInventoryScope,
    StaticSemanticOperation,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


PHASE10D_STATIC_SEMANTIC_GRAPH_PROJECTION_CONTRACT = (
    "phase10d_static_semantic_graph_projection_v1"
)
PHASE10D_STATIC_SEMANTIC_GRAPH_MATERIALIZATION_CONTRACT = (
    "phase10d_static_semantic_graph_materialization_v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HEX_ADDRESS = re.compile(r"^0x[0-9a-fA-F]+$")
_HEX_BYTES = re.compile(r"^0x(?:[0-9a-fA-F]{2})+$")
_FORBIDDEN_OUTCOME_FRAGMENTS = (
    "attack_chain",
    "causes",
    "causal_result",
    "exploit",
    "runtime_executed",
    "triggerable",
    "verified",
    "vulnerable",
)


class StaticSemanticGraphNodeKind(str, Enum):
    """Closed node vocabulary for projection v1."""

    FUNCTION = "function"
    BASIC_BLOCK = "basic_block"
    SEMANTIC_INSTRUCTION_FACT = "semantic_instruction_fact"


class StaticSemanticGraphRelationKind(str, Enum):
    """Closed, non-causal containment vocabulary for projection v1."""

    FUNCTION_CONTAINS_BASIC_BLOCK = "function_contains_basic_block"
    BASIC_BLOCK_CONTAINS_SEMANTIC_FACT = (
        "basic_block_contains_semantic_fact"
    )
    FUNCTION_CONTAINS_SEMANTIC_FACT = "function_contains_semantic_fact"


class StaticSemanticGraphProjectionScope(str, Enum):
    """Honest completeness boundary for the projected inventory graph."""

    PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY_GRAPH = (
        "partial_audited_static_semantic_inventory_graph"
    )


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _semantic_id(prefix: str, payload: object) -> str:
    digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return f"{prefix}:{digest}"


def _canonical_sha256(value: str) -> str:
    candidate = value.strip()
    if not _SHA256.fullmatch(candidate):
        raise ValueError("SHA-256 must contain 64 lowercase hexadecimal digits")
    return candidate


def _canonical_address(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("static semantic graph address must be hexadecimal")
    candidate = value.strip()
    if not _HEX_ADDRESS.fullmatch(candidate):
        raise ValueError("static semantic graph address must use hexadecimal notation")
    return hex(int(candidate, 16))


def _canonical_instruction_bytes(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("instruction bytes must be a hexadecimal string")
    candidate = value.strip()
    if not _HEX_BYTES.fullmatch(candidate):
        raise ValueError(
            "instruction bytes must use 0x plus an even number of hex digits"
        )
    return candidate.lower()


def _reject_path_like_identifier(value: str, *, label: str) -> str:
    lowered = value.lower()
    if "/" in value or "\\" in value or lowered.startswith(("file:", "~")):
        raise ValueError(f"{label} must be path-neutral")
    return value


def _reject_outcome_like_value(value: str, *, label: str) -> str:
    lowered = value.lower()
    if any(item in lowered for item in _FORBIDDEN_OUTCOME_FRAGMENTS):
        raise ValueError(f"{label} must be outcome-neutral")
    return value


def static_semantic_graph_node_id(payload: object) -> str:
    """Return one deterministic inventory-graph node identity."""

    return _semantic_id("static-semantic-graph-node", payload)


def static_semantic_graph_relation_id(payload: object) -> str:
    """Return one deterministic inventory-graph relation identity."""

    return _semantic_id("static-semantic-graph-relation", payload)


def static_semantic_graph_projection_id(payload: object) -> str:
    """Return one deterministic inventory-graph projection identity."""

    return _semantic_id("static-semantic-graph-projection", payload)


class _StaticSemanticGraphNodeBody(DomainModel):
    kind: StaticSemanticGraphNodeKind
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    source_inventory_id: Identifier
    source_fact_ids: list[Identifier] = Field(min_length=1)
    function_address: Identifier | None = None
    function_name: Identifier | None = None
    basic_block_address: Identifier | None = None
    instruction_address: Identifier | None = None
    instruction_bytes: Identifier | None = None
    instruction_size: int | None = Field(default=None, ge=1)
    operation: StaticSemanticOperation | None = None
    attributes: list[StaticSemanticAttribute] = Field(default_factory=list)
    fact_scope: StaticSemanticFactScope | None = None

    @field_validator("artifact_id", "source_inventory_id", "function_name")
    @classmethod
    def validate_path_neutral_identifier(
        cls, value: str | None
    ) -> str | None:
        if value is None:
            return None
        return _reject_path_like_identifier(
            value, label="static semantic graph identifier"
        )

    @field_validator("source_fact_ids")
    @classmethod
    def normalize_source_fact_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("graph node source fact IDs must be unique")
        return sorted(
            _reject_path_like_identifier(
                value, label="graph node source fact ID"
            )
            for value in values
        )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator(
        "function_address",
        "basic_block_address",
        "instruction_address",
        mode="before",
    )
    @classmethod
    def normalize_address(cls, value: object) -> str | None:
        return _canonical_address(value)

    @field_validator("instruction_bytes", mode="before")
    @classmethod
    def normalize_instruction_bytes(cls, value: object) -> str | None:
        return _canonical_instruction_bytes(value)

    @field_validator("attributes")
    @classmethod
    def normalize_attributes(
        cls, values: list[StaticSemanticAttribute]
    ) -> list[StaticSemanticAttribute]:
        names = [item.name for item in values]
        if len(names) != len(set(names)):
            raise ValueError("graph semantic attribute names must be unique")
        return sorted(values, key=lambda item: (item.name.value, item.value))

    @model_validator(mode="after")
    def validate_kind_shape(self) -> "_StaticSemanticGraphNodeBody":
        semantic_fields = (
            self.instruction_address,
            self.instruction_bytes,
            self.instruction_size,
            self.operation,
            self.fact_scope,
        )
        if self.kind is StaticSemanticGraphNodeKind.FUNCTION:
            if self.function_address is None:
                raise ValueError("function node requires a function address")
            if self.basic_block_address is not None or any(
                value is not None for value in semantic_fields
            ) or self.attributes:
                raise ValueError("function node carries block or instruction semantics")
        elif self.kind is StaticSemanticGraphNodeKind.BASIC_BLOCK:
            if self.basic_block_address is None:
                raise ValueError("basic-block node requires a block address")
            if self.function_name is not None and self.function_address is None:
                raise ValueError("basic-block function name requires function address")
            if any(value is not None for value in semantic_fields) or self.attributes:
                raise ValueError("basic-block node carries instruction semantics")
        else:
            if any(value is None for value in semantic_fields):
                raise ValueError("semantic-fact node is missing source semantic fields")
            if len(self.source_fact_ids) != 1:
                raise ValueError("semantic-fact node requires exactly one source fact")
            if self.function_name is not None and self.function_address is None:
                raise ValueError("semantic-fact function name requires function address")
            if (len(self.instruction_bytes or "") - 2) // 2 != self.instruction_size:
                raise ValueError(
                    "semantic-fact instruction byte length does not match size"
                )
        return self


class StaticSemanticGraphNode(_StaticSemanticGraphNodeBody):
    """One source-supported node in an inventory graph."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticSemanticGraphNode":
        body = _StaticSemanticGraphNodeBody.model_validate(values)
        payload = body.model_dump(mode="json")
        return cls(id=static_semantic_graph_node_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticSemanticGraphNode":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_semantic_graph_node_id(payload):
            raise ValueError("static semantic graph node ID mismatch")
        return self


class _StaticSemanticGraphRelationBody(DomainModel):
    relation_kind: StaticSemanticGraphRelationKind
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    source_inventory_id: Identifier
    source_node_id: Identifier
    target_node_id: Identifier
    source_fact_ids: list[Identifier] = Field(min_length=1)
    causal: Literal[False] = False
    runtime_execution: Literal[False] = False
    symbolic_feasibility: Literal[False] = False

    @field_validator(
        "artifact_id", "source_inventory_id", "source_node_id", "target_node_id"
    )
    @classmethod
    def validate_path_neutral_identifier(cls, value: str) -> str:
        return _reject_path_like_identifier(
            value, label="static semantic relation identifier"
        )

    @field_validator("source_fact_ids")
    @classmethod
    def normalize_source_fact_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("graph relation source fact IDs must be unique")
        return sorted(
            _reject_path_like_identifier(
                value, label="graph relation source fact ID"
            )
            for value in values
        )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)


class StaticSemanticGraphRelation(_StaticSemanticGraphRelationBody):
    """One explicitly non-causal static containment relation."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticSemanticGraphRelation":
        body = _StaticSemanticGraphRelationBody.model_validate(values)
        payload = body.model_dump(mode="json")
        return cls(id=static_semantic_graph_relation_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticSemanticGraphRelation":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_semantic_graph_relation_id(payload):
            raise ValueError("static semantic graph relation ID mismatch")
        return self


_NODE_KIND_ORDER = {
    StaticSemanticGraphNodeKind.FUNCTION: 0,
    StaticSemanticGraphNodeKind.BASIC_BLOCK: 1,
    StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT: 2,
}


def _node_sort_key(node: StaticSemanticGraphNode) -> tuple[object, ...]:
    return (
        _NODE_KIND_ORDER[node.kind],
        int(node.function_address or "0x0", 16),
        int(node.basic_block_address or "0x0", 16),
        int(node.instruction_address or "0x0", 16),
        node.id,
    )


def _relation_sort_key(
    relation: StaticSemanticGraphRelation,
) -> tuple[str, str, str, str]:
    return (
        relation.relation_kind.value,
        relation.source_node_id,
        relation.target_node_id,
        relation.id,
    )


def static_semantic_graph_diagnostics(
    nodes: list[StaticSemanticGraphNode],
    relations: list[StaticSemanticGraphRelation],
) -> list[str]:
    """Return exact deterministic projection diagnostics."""

    function_count = sum(
        item.kind is StaticSemanticGraphNodeKind.FUNCTION for item in nodes
    )
    block_count = sum(
        item.kind is StaticSemanticGraphNodeKind.BASIC_BLOCK for item in nodes
    )
    fact_count = sum(
        item.kind is StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT
        for item in nodes
    )
    relation_counts = {
        kind: sum(item.relation_kind is kind for item in relations)
        for kind in StaticSemanticGraphRelationKind
    }
    contained_fact_ids = {
        item.target_node_id
        for item in relations
        if item.relation_kind
        in {
            StaticSemanticGraphRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT,
            StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT,
        }
    }
    uncontained_count = sum(
        item.kind is StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT
        and item.id not in contained_fact_ids
        for item in nodes
    )
    return sorted(
        [
            f"source_inventory_fact_count:{fact_count}",
            f"function_node_count:{function_count}",
            f"basic_block_node_count:{block_count}",
            f"semantic_fact_node_count:{fact_count}",
            "function_contains_basic_block_relation_count:"
            f"{relation_counts[StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK]}",
            "basic_block_contains_semantic_fact_relation_count:"
            f"{relation_counts[StaticSemanticGraphRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT]}",
            "function_contains_semantic_fact_relation_count:"
            f"{relation_counts[StaticSemanticGraphRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT]}",
            f"uncontained_semantic_fact_node_count:{uncontained_count}",
        ]
    )


class _StaticSemanticGraphProjectionBody(DomainModel):
    contract: Literal[PHASE10D_STATIC_SEMANTIC_GRAPH_PROJECTION_CONTRACT]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    source_inventory_id: Identifier
    source_inventory_contract: Literal[
        PHASE10D_STATIC_SEMANTIC_INVENTORY_CONTRACT
    ]
    decoder_profile_id: Identifier
    instruction_set: Identifier
    source_inventory_scope: Literal[
        StaticSemanticInventoryScope.PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY
    ]
    nodes: list[StaticSemanticGraphNode] = Field(default_factory=list)
    relations: list[StaticSemanticGraphRelation] = Field(default_factory=list)
    projection_scope: Literal[
        StaticSemanticGraphProjectionScope
        .PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY_GRAPH
    ]
    diagnostic_codes: list[Identifier]

    @field_validator(
        "artifact_id", "source_inventory_id", "decoder_profile_id", "instruction_set"
    )
    @classmethod
    def validate_path_neutral_identifier(cls, value: str) -> str:
        return _reject_path_like_identifier(
            value, label="static semantic graph provenance identifier"
        )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("nodes")
    @classmethod
    def normalize_nodes(
        cls, values: list[StaticSemanticGraphNode]
    ) -> list[StaticSemanticGraphNode]:
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("static semantic graph node IDs must be unique")
        return sorted(values, key=_node_sort_key)

    @field_validator("relations")
    @classmethod
    def normalize_relations(
        cls, values: list[StaticSemanticGraphRelation]
    ) -> list[StaticSemanticGraphRelation]:
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("static semantic graph relation IDs must be unique")
        logical_keys = [
            (item.relation_kind, item.source_node_id, item.target_node_id)
            for item in values
        ]
        if len(logical_keys) != len(set(logical_keys)):
            raise ValueError("static semantic graph relations must be logically unique")
        return sorted(values, key=_relation_sort_key)

    @field_validator("diagnostic_codes")
    @classmethod
    def normalize_diagnostics(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("static semantic graph diagnostics must be unique")
        normalized = []
        for value in values:
            value = _reject_path_like_identifier(
                value, label="static semantic graph diagnostic"
            )
            normalized.append(
                _reject_outcome_like_value(
                    value, label="static semantic graph diagnostic"
                )
            )
        return sorted(normalized)

    @model_validator(mode="after")
    def validate_graph_integrity(self) -> "_StaticSemanticGraphProjectionBody":
        node_by_id = {item.id: item for item in self.nodes}
        semantic_nodes = [
            item
            for item in self.nodes
            if item.kind
            is StaticSemanticGraphNodeKind.SEMANTIC_INSTRUCTION_FACT
        ]
        semantic_source_ids = [item.source_fact_ids[0] for item in semantic_nodes]
        if len(semantic_source_ids) != len(set(semantic_source_ids)):
            raise ValueError("source semantic facts must project exactly once")
        semantic_source_set = set(semantic_source_ids)

        for node in self.nodes:
            if node.architecture is not self.architecture:
                raise ValueError("static semantic graph node architecture mismatch")
            if (
                node.artifact_id,
                node.artifact_sha256,
                node.source_inventory_id,
            ) != (
                self.artifact_id,
                self.artifact_sha256,
                self.source_inventory_id,
            ):
                raise ValueError("static semantic graph node provenance mismatch")
            if not set(node.source_fact_ids).issubset(semantic_source_set):
                raise ValueError("graph node has unsupported source fact IDs")

        functions = [
            item
            for item in self.nodes
            if item.kind is StaticSemanticGraphNodeKind.FUNCTION
        ]
        function_by_address = {item.function_address: item for item in functions}
        if len(function_by_address) != len(functions):
            raise ValueError("function addresses must project exactly once")
        blocks = [
            item
            for item in self.nodes
            if item.kind is StaticSemanticGraphNodeKind.BASIC_BLOCK
        ]
        block_by_key = {
            (item.function_address, item.basic_block_address): item
            for item in blocks
        }
        if len(block_by_key) != len(blocks):
            raise ValueError("function-scoped block identities must be unique")

        function_support: dict[str, set[str]] = {}
        function_names: dict[str, set[str]] = {}
        block_support: dict[tuple[str | None, str], set[str]] = {}
        for node in semantic_nodes:
            source_fact_id = node.source_fact_ids[0]
            if node.function_address is not None:
                function_support.setdefault(node.function_address, set()).add(
                    source_fact_id
                )
                if node.function_name is not None:
                    function_names.setdefault(node.function_address, set()).add(
                        node.function_name
                    )
            if node.basic_block_address is not None:
                block_support.setdefault(
                    (node.function_address, node.basic_block_address), set()
                ).add(source_fact_id)

        if set(function_by_address) != set(function_support):
            raise ValueError("function nodes do not exactly cover semantic provenance")
        if set(block_by_key) != set(block_support):
            raise ValueError("basic-block nodes do not exactly cover semantic provenance")
        for address, support in function_support.items():
            names = function_names.get(address, set())
            if len(names) > 1:
                raise ValueError("conflicting function names share one address")
            expected_name = next(iter(names), None)
            function = function_by_address[address]
            if set(function.source_fact_ids) != support or (
                function.function_name != expected_name
            ):
                raise ValueError("function node source support is not exact")
        for key, support in block_support.items():
            block = block_by_key[key]
            expected_name = (
                function_by_address[key[0]].function_name
                if key[0] is not None
                else None
            )
            if set(block.source_fact_ids) != support or (
                block.function_name != expected_name
            ):
                raise ValueError("basic-block node source support is not exact")

        relation_by_key = {
            (item.relation_kind, item.source_node_id, item.target_node_id): item
            for item in self.relations
        }
        for relation in self.relations:
            if relation.source_node_id not in node_by_id or (
                relation.target_node_id not in node_by_id
            ):
                raise ValueError(
                    "static semantic graph relation has dangling endpoint"
                )
            if (
                relation.architecture is not self.architecture
                or relation.artifact_id != self.artifact_id
                or relation.artifact_sha256 != self.artifact_sha256
                or relation.source_inventory_id != self.source_inventory_id
            ):
                raise ValueError(
                    "static semantic graph relation provenance mismatch"
                )
        expected_relations: dict[
            tuple[StaticSemanticGraphRelationKind, str, str], set[str]
        ] = {}
        for key, block in block_by_key.items():
            function_address, _ = key
            if function_address is not None:
                function = function_by_address[function_address]
                expected_relations[
                    (
                        StaticSemanticGraphRelationKind
                        .FUNCTION_CONTAINS_BASIC_BLOCK,
                        function.id,
                        block.id,
                    )
                ] = set(block.source_fact_ids)
        for fact in semantic_nodes:
            source_ids = set(fact.source_fact_ids)
            if fact.basic_block_address is not None:
                block = block_by_key[
                    (fact.function_address, fact.basic_block_address)
                ]
                expected_relations[
                    (
                        StaticSemanticGraphRelationKind
                        .BASIC_BLOCK_CONTAINS_SEMANTIC_FACT,
                        block.id,
                        fact.id,
                    )
                ] = source_ids
            elif fact.function_address is not None:
                function = function_by_address[fact.function_address]
                expected_relations[
                    (
                        StaticSemanticGraphRelationKind
                        .FUNCTION_CONTAINS_SEMANTIC_FACT,
                        function.id,
                        fact.id,
                    )
                ] = source_ids

        if set(relation_by_key) != set(expected_relations):
            raise ValueError("static semantic containment relations are not exact")
        for key, expected_support in expected_relations.items():
            relation = relation_by_key[key]
            if set(relation.source_fact_ids) != expected_support:
                raise ValueError("graph relation source support is not exact")

        expected_diagnostics = static_semantic_graph_diagnostics(
            self.nodes, self.relations
        )
        if self.diagnostic_codes != expected_diagnostics:
            raise ValueError("static semantic graph diagnostics do not match contents")
        return self


class StaticSemanticGraphProjection(_StaticSemanticGraphProjectionBody):
    """Lossless graph projection of available audited semantic facts."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticSemanticGraphProjection":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_SEMANTIC_GRAPH_PROJECTION_CONTRACT
        )
        body = _StaticSemanticGraphProjectionBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_semantic_graph_projection_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticSemanticGraphProjection":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_semantic_graph_projection_id(payload):
            raise ValueError("static semantic graph projection ID mismatch")
        return self
