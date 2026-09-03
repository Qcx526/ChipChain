"""Architecture-neutral contracts for provenance-bound static graph fusion."""

from __future__ import annotations

from enum import Enum
import hashlib
import json
import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.analysis.static_program_structure_models import (
    StaticProgramCfgSemantics,
    StaticProgramStructureInventoryScope,
)
from chipchain.analysis.static_semantic_models import (
    StaticSemanticAttribute,
    StaticSemanticFactScope,
    StaticSemanticInventoryScope,
    StaticSemanticOperation,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


PHASE10D_STATIC_FUSED_BEHAVIOR_NODE_CONTRACT = (
    "phase10d_static_fused_behavior_node_v1"
)
PHASE10D_STATIC_FUSED_BEHAVIOR_RELATION_CONTRACT = (
    "phase10d_static_fused_behavior_relation_v1"
)
PHASE10D_STATIC_FUSED_BEHAVIOR_GRAPH_PROJECTION_CONTRACT = (
    "phase10d_static_fused_behavior_graph_projection_v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HEX_ADDRESS = re.compile(r"^0x[0-9a-fA-F]+$")
_HEX_BYTES = re.compile(r"^0x(?:[0-9a-fA-F]{2})+$")
_FORBIDDEN_OUTCOME_FRAGMENTS = (
    "attack_chain",
    "causes",
    "confidence",
    "coverage_score",
    "exploit",
    "triggerable",
    "verified",
    "vulnerable",
)


class StaticFusedBehaviorNodeKind(str, Enum):
    """Closed v1 node vocabulary for the fused static graph."""

    FUNCTION = "function"
    BASIC_BLOCK = "basic_block"
    SEMANTIC_INSTRUCTION_FACT = "semantic_instruction_fact"


class StaticFusedBehaviorRelationKind(str, Enum):
    """Closed v1 relation vocabulary for the fused static graph."""

    FUNCTION_CONTAINS_BASIC_BLOCK = "function_contains_basic_block"
    BASIC_BLOCK_CONTAINS_SEMANTIC_FACT = (
        "basic_block_contains_semantic_fact"
    )
    FUNCTION_CONTAINS_SEMANTIC_FACT = "function_contains_semantic_fact"
    CFG_SUCCESSOR = "cfg_successor"


class StaticFusedBehaviorProjectionScope(str, Enum):
    """Honest completeness boundary for one fused static projection."""

    PARTIAL_PROVENANCE_BOUND_SEMANTIC_STRUCTURE_STATIC_BEHAVIOR_GRAPH = (
        "partial_provenance_bound_semantic_structure_static_behavior_graph"
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
        raise ValueError("fused static graph address must be hexadecimal")
    candidate = value.strip()
    if not _HEX_ADDRESS.fullmatch(candidate):
        raise ValueError("fused static graph address must use hexadecimal notation")
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


def _validate_identifier(value: str, *, label: str) -> str:
    lowered = value.lower()
    if "/" in value or "\\" in value or lowered.startswith(("file:", "~")):
        raise ValueError(f"{label} must be path-neutral")
    if any(fragment in lowered for fragment in _FORBIDDEN_OUTCOME_FRAGMENTS):
        raise ValueError(f"{label} must be outcome-neutral")
    return value


def _normalize_identifiers(values: list[str], *, label: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
    return sorted(_validate_identifier(value, label=label) for value in values)


def static_fused_behavior_node_id(payload: object) -> str:
    """Return one deterministic fused-node identity."""

    return _semantic_id("static-fused-behavior-node", payload)


def static_fused_behavior_relation_id(payload: object) -> str:
    """Return one deterministic fused-relation identity."""

    return _semantic_id("static-fused-behavior-relation", payload)


def static_fused_behavior_graph_projection_id(payload: object) -> str:
    """Return one deterministic fused-projection identity."""

    return _semantic_id("static-fused-behavior-graph-projection", payload)


class _StaticFusedBehaviorNodeBody(DomainModel):
    contract: Literal["phase10d_static_fused_behavior_node_v1"]
    kind: Literal[
        StaticFusedBehaviorNodeKind.FUNCTION,
        StaticFusedBehaviorNodeKind.BASIC_BLOCK,
        StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT,
    ]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    instruction_set: Identifier
    function_address: Identifier | None = None
    function_name: Identifier | None = None
    basic_block_address: Identifier | None = None
    instruction_address: Identifier | None = None
    instruction_bytes: Identifier | None = None
    instruction_size: int | None = Field(default=None, ge=1)
    operation: StaticSemanticOperation | None = None
    attributes: list[StaticSemanticAttribute] = Field(default_factory=list)
    fact_scope: StaticSemanticFactScope | None = None
    semantic_source_node_ids: list[Identifier] = Field(default_factory=list)
    semantic_source_fact_ids: list[Identifier] = Field(default_factory=list)
    structure_function_cfg_ids: list[Identifier] = Field(default_factory=list)
    structure_basic_block_source_ids: list[Identifier] = Field(
        default_factory=list
    )

    @field_validator("artifact_id", "instruction_set", "function_name")
    @classmethod
    def validate_identifier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_identifier(value, label="fused node identifier")

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
        detached = [
            StaticSemanticAttribute.model_validate(item.model_dump(mode="json"))
            for item in values
        ]
        names = [item.name for item in detached]
        if len(names) != len(set(names)):
            raise ValueError("fused semantic attribute names must be unique")
        return sorted(detached, key=lambda item: (item.name.value, item.value))

    @field_validator(
        "semantic_source_node_ids",
        "semantic_source_fact_ids",
        "structure_function_cfg_ids",
        "structure_basic_block_source_ids",
    )
    @classmethod
    def normalize_source_ids(cls, values: list[str]) -> list[str]:
        return _normalize_identifiers(values, label="fused node source IDs")

    @model_validator(mode="after")
    def validate_kind_and_provenance(self) -> "_StaticFusedBehaviorNodeBody":
        semantic_fields = (
            self.instruction_address,
            self.instruction_bytes,
            self.instruction_size,
            self.operation,
            self.fact_scope,
        )
        if len(self.semantic_source_node_ids) > 1:
            raise ValueError("fused node has multiple semantic source nodes")
        if len(self.structure_function_cfg_ids) > 1:
            raise ValueError("fused node has multiple structure function sources")
        if len(self.structure_basic_block_source_ids) > 1:
            raise ValueError("fused node has multiple structure block sources")

        semantic_supported = bool(self.semantic_source_node_ids)
        semantic_facts = bool(self.semantic_source_fact_ids)
        structure_function = bool(self.structure_function_cfg_ids)
        structure_block = bool(self.structure_basic_block_source_ids)

        if self.kind is StaticFusedBehaviorNodeKind.FUNCTION:
            if self.function_address is None:
                raise ValueError("fused function node requires function address")
            if self.basic_block_address is not None or any(
                value is not None for value in semantic_fields
            ) or self.attributes:
                raise ValueError("fused function node carries block or fact fields")
            if semantic_supported != semantic_facts:
                raise ValueError("fused function semantic provenance is incomplete")
            if structure_block:
                raise ValueError("fused function node carries structure block source")
            if not semantic_supported and not structure_function:
                raise ValueError("fused function node has no source provenance")
        elif self.kind is StaticFusedBehaviorNodeKind.BASIC_BLOCK:
            if self.basic_block_address is None:
                raise ValueError("fused basic-block node requires block address")
            if self.function_name is not None and self.function_address is None:
                raise ValueError("unscoped fused block cannot carry function name")
            if any(value is not None for value in semantic_fields) or self.attributes:
                raise ValueError("fused basic-block node carries semantic fact fields")
            if semantic_supported != semantic_facts:
                raise ValueError("fused block semantic provenance is incomplete")
            if structure_function != structure_block:
                raise ValueError("fused block structure provenance is incomplete")
            if structure_block and self.function_address is None:
                raise ValueError("unscoped fused block has structure provenance")
            if not semantic_supported and not structure_block:
                raise ValueError("fused basic-block node has no source provenance")
        else:
            if any(value is None for value in semantic_fields):
                raise ValueError("fused semantic-fact node is incomplete")
            if len(self.semantic_source_node_ids) != 1 or len(
                self.semantic_source_fact_ids
            ) != 1:
                raise ValueError("fused semantic-fact source must be exact")
            if structure_function or structure_block:
                raise ValueError("structure source cannot create semantic facts")
            if self.function_name is not None and self.function_address is None:
                raise ValueError("semantic-fact function name requires address")
            if (len(self.instruction_bytes or "") - 2) // 2 != (
                self.instruction_size
            ):
                raise ValueError("semantic-fact byte length does not match size")
        return self


class StaticFusedBehaviorNode(_StaticFusedBehaviorNodeBody):
    """One exact source-supported node in the fused static graph."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticFusedBehaviorNode":
        body_values = dict(values)
        body_values["contract"] = PHASE10D_STATIC_FUSED_BEHAVIOR_NODE_CONTRACT
        body = _StaticFusedBehaviorNodeBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_fused_behavior_node_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticFusedBehaviorNode":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_fused_behavior_node_id(payload):
            raise ValueError("static fused behavior node ID mismatch")
        return self


class _StaticFusedBehaviorRelationBody(DomainModel):
    contract: Literal["phase10d_static_fused_behavior_relation_v1"]
    relation_kind: Literal[
        StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK,
        StaticFusedBehaviorRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT,
        StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT,
        StaticFusedBehaviorRelationKind.CFG_SUCCESSOR,
    ]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    instruction_set: Identifier
    source_node_id: Identifier
    target_node_id: Identifier
    semantic_source_relation_ids: list[Identifier] = Field(default_factory=list)
    structure_function_cfg_ids: list[Identifier] = Field(default_factory=list)
    structure_basic_block_source_ids: list[Identifier] = Field(
        default_factory=list
    )
    structure_cfg_edge_ids: list[Identifier] = Field(default_factory=list)
    cfg_semantics: Literal[
        StaticProgramCfgSemantics
        .FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1
    ] | None = None
    causal: Literal[False] = False
    runtime_execution: Literal[False] = False
    symbolic_feasibility: Literal[False] = False

    @field_validator(
        "artifact_id", "instruction_set", "source_node_id", "target_node_id"
    )
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_identifier(value, label="fused relation identifier")

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator(
        "semantic_source_relation_ids",
        "structure_function_cfg_ids",
        "structure_basic_block_source_ids",
        "structure_cfg_edge_ids",
    )
    @classmethod
    def normalize_source_ids(cls, values: list[str]) -> list[str]:
        return _normalize_identifiers(values, label="fused relation source IDs")

    @model_validator(mode="after")
    def validate_relation_provenance(
        self,
    ) -> "_StaticFusedBehaviorRelationBody":
        semantic_count = len(self.semantic_source_relation_ids)
        function_count = len(self.structure_function_cfg_ids)
        block_count = len(self.structure_basic_block_source_ids)
        edge_count = len(self.structure_cfg_edge_ids)
        if semantic_count > 1 or function_count > 1 or edge_count > 1:
            raise ValueError("fused relation provenance is not singular")
        if block_count > 2:
            raise ValueError("fused relation has too many structure block sources")

        if self.relation_kind is (
            StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK
        ):
            if bool(function_count) != bool(block_count):
                raise ValueError("function/block membership provenance is incomplete")
            if not semantic_count and not function_count:
                raise ValueError("fused membership relation has no source")
            if edge_count or self.cfg_semantics is not None:
                raise ValueError("fused membership relation carries CFG provenance")
        elif self.relation_kind in {
            StaticFusedBehaviorRelationKind
            .BASIC_BLOCK_CONTAINS_SEMANTIC_FACT,
            StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT,
        }:
            if semantic_count != 1:
                raise ValueError("semantic containment requires exact source relation")
            if function_count or block_count or edge_count:
                raise ValueError("structure source cannot create semantic containment")
            if self.cfg_semantics is not None:
                raise ValueError("semantic containment carries CFG semantics")
        else:
            if semantic_count:
                raise ValueError("CFG successor cannot have semantic relation source")
            if function_count != 1 or edge_count != 1 or not block_count:
                raise ValueError("CFG successor structure provenance is incomplete")
            if self.cfg_semantics is None:
                raise ValueError("CFG successor requires exact CFG semantics")
        return self


class StaticFusedBehaviorRelation(_StaticFusedBehaviorRelationBody):
    """One exact static containment or objective CFG relation."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticFusedBehaviorRelation":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_FUSED_BEHAVIOR_RELATION_CONTRACT
        )
        body = _StaticFusedBehaviorRelationBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_fused_behavior_relation_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticFusedBehaviorRelation":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_fused_behavior_relation_id(payload):
            raise ValueError("static fused behavior relation ID mismatch")
        return self


_NODE_KIND_ORDER = {
    StaticFusedBehaviorNodeKind.FUNCTION: 0,
    StaticFusedBehaviorNodeKind.BASIC_BLOCK: 1,
    StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT: 2,
}


def _node_sort_key(node: StaticFusedBehaviorNode) -> tuple[object, ...]:
    return (
        _NODE_KIND_ORDER[node.kind],
        node.function_address is None,
        int(node.function_address or "0x0", 16),
        int(node.basic_block_address or "0x0", 16),
        int(node.instruction_address or "0x0", 16),
        node.id,
    )


def _relation_sort_key(
    relation: StaticFusedBehaviorRelation,
) -> tuple[str, str, str, str]:
    return (
        relation.relation_kind.value,
        relation.source_node_id,
        relation.target_node_id,
        relation.id,
    )


def static_fused_behavior_diagnostics(
    nodes: list[StaticFusedBehaviorNode],
    relations: list[StaticFusedBehaviorRelation],
) -> list[str]:
    """Return exact deterministic fused-graph diagnostics."""

    node_counts = {
        kind: sum(node.kind is kind for node in nodes)
        for kind in StaticFusedBehaviorNodeKind
    }
    relation_counts = {
        kind: sum(relation.relation_kind is kind for relation in relations)
        for kind in StaticFusedBehaviorRelationKind
    }
    function_block_count = relation_counts[
        StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK
    ]
    block_fact_count = relation_counts[
        StaticFusedBehaviorRelationKind.BASIC_BLOCK_CONTAINS_SEMANTIC_FACT
    ]
    function_fact_count = relation_counts[
        StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT
    ]

    def support_count(
        kind: StaticFusedBehaviorNodeKind,
        semantic: bool,
        structure: bool,
    ) -> int:
        return sum(
            node.kind is kind
            and bool(node.semantic_source_node_ids) is semantic
            and bool(node.structure_function_cfg_ids) is structure
            for node in nodes
        )

    return sorted(
        [
            f"function_node_count:{node_counts[StaticFusedBehaviorNodeKind.FUNCTION]}",
            "basic_block_node_count:"
            f"{node_counts[StaticFusedBehaviorNodeKind.BASIC_BLOCK]}",
            "semantic_fact_node_count:"
            f"{node_counts[StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT]}",
            "function_contains_basic_block_relation_count:"
            f"{function_block_count}",
            "basic_block_contains_semantic_fact_relation_count:"
            f"{block_fact_count}",
            "function_contains_semantic_fact_relation_count:"
            f"{function_fact_count}",
            "cfg_successor_relation_count:"
            f"{relation_counts[StaticFusedBehaviorRelationKind.CFG_SUCCESSOR]}",
            "semantic_only_function_node_count:"
            f"{support_count(StaticFusedBehaviorNodeKind.FUNCTION, True, False)}",
            "structure_only_function_node_count:"
            f"{support_count(StaticFusedBehaviorNodeKind.FUNCTION, False, True)}",
            "dual_source_function_node_count:"
            f"{support_count(StaticFusedBehaviorNodeKind.FUNCTION, True, True)}",
            "semantic_only_basic_block_node_count:"
            f"{support_count(StaticFusedBehaviorNodeKind.BASIC_BLOCK, True, False)}",
            "structure_only_basic_block_node_count:"
            f"{support_count(StaticFusedBehaviorNodeKind.BASIC_BLOCK, False, True)}",
            "dual_source_basic_block_node_count:"
            f"{support_count(StaticFusedBehaviorNodeKind.BASIC_BLOCK, True, True)}",
        ]
    )


class _StaticFusedBehaviorGraphProjectionBody(DomainModel):
    contract: Literal[
        "phase10d_static_fused_behavior_graph_projection_v1"
    ]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    instruction_set: Identifier
    semantic_inventory_id: Identifier
    semantic_graph_projection_id: Identifier
    semantic_graph_materialization_id: Identifier
    decoder_profile_id: Identifier
    semantic_source_scope: Literal[
        StaticSemanticInventoryScope.PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY
    ]
    structure_inventory_id: Identifier
    structure_analyzer_profile_id: Identifier
    structure_source_scope: Literal[
        StaticProgramStructureInventoryScope
        .PARTIAL_OBJECTIVE_FUNCTION_LOCAL_CFG_INVENTORY
    ]
    nodes: list[StaticFusedBehaviorNode] = Field(default_factory=list)
    relations: list[StaticFusedBehaviorRelation] = Field(default_factory=list)
    projection_scope: Literal[
        StaticFusedBehaviorProjectionScope
        .PARTIAL_PROVENANCE_BOUND_SEMANTIC_STRUCTURE_STATIC_BEHAVIOR_GRAPH
    ]
    diagnostic_codes: list[Identifier]

    @field_validator(
        "artifact_id",
        "instruction_set",
        "semantic_inventory_id",
        "semantic_graph_projection_id",
        "semantic_graph_materialization_id",
        "decoder_profile_id",
        "structure_inventory_id",
        "structure_analyzer_profile_id",
    )
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_identifier(value, label="fused projection identifier")

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("nodes")
    @classmethod
    def normalize_nodes(
        cls, values: list[StaticFusedBehaviorNode]
    ) -> list[StaticFusedBehaviorNode]:
        detached = [
            StaticFusedBehaviorNode.model_validate(item.model_dump(mode="json"))
            for item in values
        ]
        ids = [item.id for item in detached]
        if len(ids) != len(set(ids)):
            raise ValueError("fused graph node IDs must be unique")
        return sorted(detached, key=_node_sort_key)

    @field_validator("relations")
    @classmethod
    def normalize_relations(
        cls, values: list[StaticFusedBehaviorRelation]
    ) -> list[StaticFusedBehaviorRelation]:
        detached = [
            StaticFusedBehaviorRelation.model_validate(
                item.model_dump(mode="json")
            )
            for item in values
        ]
        ids = [item.id for item in detached]
        if len(ids) != len(set(ids)):
            raise ValueError("fused graph relation IDs must be unique")
        logical = [
            (item.relation_kind, item.source_node_id, item.target_node_id)
            for item in detached
        ]
        if len(logical) != len(set(logical)):
            raise ValueError("fused graph relations must be logically unique")
        return sorted(detached, key=_relation_sort_key)

    @field_validator("diagnostic_codes")
    @classmethod
    def normalize_diagnostics(cls, values: list[str]) -> list[str]:
        return _normalize_identifiers(values, label="fused graph diagnostics")

    @model_validator(mode="after")
    def validate_graph_integrity(
        self,
    ) -> "_StaticFusedBehaviorGraphProjectionBody":
        node_by_id = {node.id: node for node in self.nodes}
        common = (
            self.architecture,
            self.artifact_id,
            self.artifact_sha256,
            self.instruction_set,
        )
        for node in self.nodes:
            if (
                node.architecture,
                node.artifact_id,
                node.artifact_sha256,
                node.instruction_set,
            ) != common:
                raise ValueError("fused node projection provenance mismatch")

        functions = [
            node
            for node in self.nodes
            if node.kind is StaticFusedBehaviorNodeKind.FUNCTION
        ]
        function_by_address = {
            node.function_address: node for node in functions
        }
        if len(function_by_address) != len(functions):
            raise ValueError("fused function addresses must be unique")
        blocks = [
            node
            for node in self.nodes
            if node.kind is StaticFusedBehaviorNodeKind.BASIC_BLOCK
        ]
        block_by_key = {
            (node.function_address, node.basic_block_address): node
            for node in blocks
        }
        if len(block_by_key) != len(blocks):
            raise ValueError("fused function-scoped block keys must be unique")
        facts = [
            node
            for node in self.nodes
            if node.kind
            is StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT
        ]
        fact_sources = [node.semantic_source_node_ids[0] for node in facts]
        if len(fact_sources) != len(set(fact_sources)):
            raise ValueError("semantic source fact nodes must project once")

        semantic_node_sources = [
            source
            for node in self.nodes
            for source in node.semantic_source_node_ids
        ]
        if len(semantic_node_sources) != len(set(semantic_node_sources)):
            raise ValueError("semantic source nodes must project exactly once")
        structure_block_sources = [
            source
            for node in blocks
            for source in node.structure_basic_block_source_ids
        ]
        if len(structure_block_sources) != len(set(structure_block_sources)):
            raise ValueError("structure block sources must project exactly once")

        semantic_relation_sources: list[str] = []
        structure_edge_sources: list[str] = []
        for relation in self.relations:
            if relation.source_node_id not in node_by_id or (
                relation.target_node_id not in node_by_id
            ):
                raise ValueError("fused relation has dangling endpoint")
            if (
                relation.architecture,
                relation.artifact_id,
                relation.artifact_sha256,
                relation.instruction_set,
            ) != common:
                raise ValueError("fused relation projection provenance mismatch")
            source = node_by_id[relation.source_node_id]
            target = node_by_id[relation.target_node_id]
            semantic_relation_sources.extend(
                relation.semantic_source_relation_ids
            )
            structure_edge_sources.extend(relation.structure_cfg_edge_ids)
            if relation.relation_kind is (
                StaticFusedBehaviorRelationKind
                .FUNCTION_CONTAINS_BASIC_BLOCK
            ):
                if source.kind is not StaticFusedBehaviorNodeKind.FUNCTION or (
                    target.kind is not StaticFusedBehaviorNodeKind.BASIC_BLOCK
                ) or source.function_address != target.function_address:
                    raise ValueError("invalid fused function/block membership")
                if relation.structure_function_cfg_ids and (
                    relation.structure_function_cfg_ids
                    != target.structure_function_cfg_ids
                    or relation.structure_basic_block_source_ids
                    != target.structure_basic_block_source_ids
                ):
                    raise ValueError("membership structure provenance mismatch")
            elif relation.relation_kind is (
                StaticFusedBehaviorRelationKind
                .BASIC_BLOCK_CONTAINS_SEMANTIC_FACT
            ):
                if source.kind is not StaticFusedBehaviorNodeKind.BASIC_BLOCK or (
                    target.kind
                    is not StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT
                ):
                    raise ValueError("invalid fused block/fact containment")
            elif relation.relation_kind is (
                StaticFusedBehaviorRelationKind.FUNCTION_CONTAINS_SEMANTIC_FACT
            ):
                if source.kind is not StaticFusedBehaviorNodeKind.FUNCTION or (
                    target.kind
                    is not StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT
                ):
                    raise ValueError("invalid fused function/fact containment")
            else:
                if source.kind is not StaticFusedBehaviorNodeKind.BASIC_BLOCK or (
                    target.kind is not StaticFusedBehaviorNodeKind.BASIC_BLOCK
                ):
                    raise ValueError("CFG successor endpoints must be blocks")
                if source.function_address is None or (
                    source.function_address != target.function_address
                ):
                    raise ValueError("CFG successor must remain function-local")
                expected_block_sources = sorted(
                    set(source.structure_basic_block_source_ids)
                    | set(target.structure_basic_block_source_ids)
                )
                if relation.structure_function_cfg_ids != (
                    source.structure_function_cfg_ids
                ) or relation.structure_function_cfg_ids != (
                    target.structure_function_cfg_ids
                ) or relation.structure_basic_block_source_ids != (
                    expected_block_sources
                ):
                    raise ValueError("CFG successor structure provenance mismatch")

        if len(semantic_relation_sources) != len(set(semantic_relation_sources)):
            raise ValueError("semantic source relations must project exactly once")
        if len(structure_edge_sources) != len(set(structure_edge_sources)):
            raise ValueError("structure CFG edges must project exactly once")
        if self.diagnostic_codes != static_fused_behavior_diagnostics(
            self.nodes, self.relations
        ):
            raise ValueError("fused graph diagnostics do not match contents")
        return self


class StaticFusedBehaviorGraphProjection(
    _StaticFusedBehaviorGraphProjectionBody
):
    """One provenance-bound union of semantic and structure static sources."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticFusedBehaviorGraphProjection":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_FUSED_BEHAVIOR_GRAPH_PROJECTION_CONTRACT
        )
        body_values.setdefault(
            "projection_scope",
            StaticFusedBehaviorProjectionScope
            .PARTIAL_PROVENANCE_BOUND_SEMANTIC_STRUCTURE_STATIC_BEHAVIOR_GRAPH,
        )
        if "diagnostic_codes" not in body_values:
            raw_nodes = body_values.get("nodes", [])
            raw_relations = body_values.get("relations", [])
            if not isinstance(raw_nodes, list) or not isinstance(
                raw_relations, list
            ):
                raise ValueError("fused nodes and relations must be lists")
            nodes = [
                StaticFusedBehaviorNode.model_validate(
                    item.model_dump(mode="json")
                )
                for item in raw_nodes
            ]
            relations = [
                StaticFusedBehaviorRelation.model_validate(
                    item.model_dump(mode="json")
                )
                for item in raw_relations
            ]
            body_values["nodes"] = nodes
            body_values["relations"] = relations
            body_values["diagnostic_codes"] = (
                static_fused_behavior_diagnostics(nodes, relations)
            )
        body = _StaticFusedBehaviorGraphProjectionBody.model_validate(
            body_values
        )
        payload = body.model_dump(mode="json")
        return cls(
            id=static_fused_behavior_graph_projection_id(payload), **payload
        )

    @model_validator(mode="after")
    def validate_deterministic_id(
        self,
    ) -> "StaticFusedBehaviorGraphProjection":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_fused_behavior_graph_projection_id(payload):
            raise ValueError("static fused behavior projection ID mismatch")
        return self
