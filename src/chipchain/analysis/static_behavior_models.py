"""Typed, outcome-neutral static program-analysis projection contracts.

These models preserve objective binary facts and structural CFG relations in a
program graph while keeping vulnerability-pattern candidates in a separate
projection.  They do not represent runtime execution, causality, verification,
triggerability, vulnerability, or attack-chain outcomes.
"""

from __future__ import annotations

from enum import Enum
import hashlib
import json
import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.hardware_trigger.a_profile_static_case_models import (
    AProfileStaticCaseAssemblyResult,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


PHASE10D_STATIC_BEHAVIOR_GRAPH_PROJECTION_CONTRACT = (
    "phase10d_static_behavior_graph_projection_v1"
)
PHASE10D_STATIC_PATTERN_BINDING_PROJECTION_CONTRACT = (
    "phase10d_static_pattern_binding_projection_v1"
)
PHASE10D_STATIC_BEHAVIOR_ANALYSIS_PROJECTION_CONTRACT = (
    "phase10d_static_behavior_analysis_projection_v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HEX_ADDRESS = re.compile(r"^0x[0-9a-fA-F]+$")
_FORBIDDEN_ASSERTION_FRAGMENTS = (
    "attack_chain",
    "causes",
    "exploits",
    "feasible_attack",
    "proximity_satisfied",
    "runtime_executed",
    "triggerable",
    "triggers",
    "verified",
    "vulnerable",
)


class StaticAssertionClass(str, Enum):
    """Closed, non-causal assertion classes emitted by projection v1."""

    OBJECTIVE_STATIC_FACT = "objective_static_fact"
    OBJECTIVE_STRUCTURAL_RELATION = "objective_structural_relation"
    DETERMINISTIC_PATTERN_CANDIDATE = "deterministic_pattern_candidate"


class StaticBehaviorNodeKind(str, Enum):
    """Closed node vocabulary for the static program graph."""

    FUNCTION = "function"
    BASIC_BLOCK = "basic_block"
    SEMANTIC_INSTRUCTION_FACT = "semantic_instruction_fact"


class StaticBehaviorRelationKind(str, Enum):
    """Closed objective structural relation vocabulary for v1."""

    FUNCTION_CONTAINS_BASIC_BLOCK = "function_contains_basic_block"
    BASIC_BLOCK_CONTAINS_SEMANTIC_FACT = (
        "basic_block_contains_semantic_fact"
    )
    CFG_SUCCESSOR = "cfg_successor"


class StaticBehaviorProjectionScope(str, Enum):
    """Scope of the static program-analysis graph projection."""

    BINARY_STATIC_PROGRAM_ANALYSIS = "binary_static_program_analysis"


class StaticPatternBindingKind(str, Enum):
    """Closed kinds of deterministic pattern-candidate references."""

    PREDICATE_CANDIDATE = "predicate_candidate"
    CASE_ORDER_CANDIDATE = "case_order_candidate"


class StaticPatternBindingSemantics(str, Enum):
    """Outcome-neutral labels for pattern-candidate projection records."""

    CANDIDATE_FOR_PATTERN_PREDICATE = (
        "candidate_for_pattern_predicate"
    )
    STATIC_ORDER_COMPATIBLE_PATTERN_CANDIDATE = (
        "static_order_compatible_pattern_candidate"
    )


class StaticPatternOrderBasis(str, Enum):
    """Closed objective structural order bases projected from C2."""

    SAME_BASIC_BLOCK_INSTRUCTION_ORDER = (
        "same_basic_block_instruction_order"
    )
    DIRECTED_FUNCTION_CFG_PATH = "directed_function_cfg_path"


class StaticPatternPathWitnessUse(str, Enum):
    """The only interpretation allowed for a projected CFG path."""

    REACHABILITY_AUDIT_ONLY = "reachability_audit_only"


class StaticObjectiveObligation(str, Enum):
    """Closed unresolved objective obligations preserved by projection v1."""

    RUNTIME_EXECUTION_REQUIRED = "runtime_execution_required"
    RUNTIME_EXECUTION_CONTEXT_REQUIRED = (
        "runtime_execution_context_required"
    )
    EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED = (
        "effective_memory_type_resolution_required"
    )
    RELATION_PROXIMITY_REMAINS_UNRESOLVED = (
        "relation_proximity_remains_unresolved"
    )
    ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED = (
        "additional_hardware_timing_remains_unresolved"
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
        raise ValueError("static program address must be a hexadecimal string")
    candidate = value.strip()
    if not _HEX_ADDRESS.fullmatch(candidate):
        raise ValueError("static program address must use hexadecimal notation")
    return candidate.lower()


def _reject_path_like_identifier(value: str, *, label: str) -> str:
    lowered = value.lower()
    if "/" in value or "\\" in value or lowered.startswith(("file:", "~")):
        raise ValueError(f"{label} must be path-neutral")
    return value


def _reject_assertion_like_identifier(value: str, *, label: str) -> str:
    lowered = value.lower()
    if any(fragment in lowered for fragment in _FORBIDDEN_ASSERTION_FRAGMENTS):
        raise ValueError(f"{label} must remain outcome-neutral")
    return value


class StaticSemanticAttributes(DomainModel):
    """Closed generic semantic attributes populated by the v1 adapter."""

    memory_type_resolution: Identifier
    static_fact_scope: Identifier
    system_register: Identifier | None = None

    @field_validator(
        "memory_type_resolution", "static_fact_scope", "system_register"
    )
    @classmethod
    def validate_neutral_value(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = _reject_path_like_identifier(
            value, label="static semantic attribute"
        )
        return _reject_assertion_like_identifier(
            value, label="static semantic attribute"
        )


def static_behavior_node_id(payload: object) -> str:
    """Return a deterministic static program-graph node identity."""

    return _semantic_id("static-behavior-node", payload)


def static_behavior_relation_id(payload: object) -> str:
    """Return a deterministic static program-graph relation identity."""

    return _semantic_id("static-behavior-relation", payload)


def static_behavior_graph_projection_id(payload: object) -> str:
    """Return a deterministic static program-graph projection identity."""

    return _semantic_id("static-behavior-graph-projection", payload)


def static_pattern_binding_record_id(payload: object) -> str:
    """Return a deterministic static pattern-binding record identity."""

    return _semantic_id("static-pattern-binding-record", payload)


def static_pattern_binding_projection_id(payload: object) -> str:
    """Return a deterministic static pattern-binding projection identity."""

    return _semantic_id("static-pattern-binding-projection", payload)


def static_behavior_analysis_projection_id(payload: object) -> str:
    """Return a deterministic top-level static analysis projection identity."""

    return _semantic_id("static-behavior-analysis-projection", payload)


def _cfg_block_source_id(cfg_id: str, block_address: str) -> str:
    return _semantic_id(
        "static-cfg-block-source",
        {"cfg_snapshot_id": cfg_id, "basic_block_address": block_address},
    )


def _cfg_edge_source_id(
    cfg_id: str, source_address: str, target_address: str
) -> str:
    return _semantic_id(
        "static-cfg-edge-source",
        {
            "cfg_snapshot_id": cfg_id,
            "source_basic_block_address": source_address,
            "target_basic_block_address": target_address,
        },
    )


class _StaticBehaviorNodeBody(DomainModel):
    kind: StaticBehaviorNodeKind
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    source_object_id: Identifier
    function_address: Identifier | None = None
    function_name: Identifier | None = None
    basic_block_address: Identifier | None = None
    instruction_address: Identifier | None = None
    instruction_word: Identifier | None = None
    instruction_size: int | None = Field(default=None, ge=1)
    semantic_operation: Identifier | None = None
    semantic_attributes: StaticSemanticAttributes | None = None
    assertion_class: Literal[StaticAssertionClass.OBJECTIVE_STATIC_FACT]

    @field_validator("artifact_id", "source_object_id")
    @classmethod
    def reject_path_identifiers(cls, value: str) -> str:
        return _reject_path_like_identifier(value, label="static node identifier")

    @field_validator("semantic_operation")
    @classmethod
    def validate_semantic_operation(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = _reject_path_like_identifier(
            value, label="static semantic operation"
        )
        return _reject_assertion_like_identifier(
            value, label="static semantic operation"
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

    @model_validator(mode="after")
    def validate_kind_shape(self) -> "_StaticBehaviorNodeBody":
        if self.kind is StaticBehaviorNodeKind.FUNCTION:
            if self.function_address is None:
                raise ValueError("function node requires function address")
            if any(
                value is not None
                for value in (
                    self.basic_block_address,
                    self.instruction_address,
                    self.instruction_word,
                    self.instruction_size,
                    self.semantic_operation,
                )
            ) or self.semantic_attributes is not None:
                raise ValueError("function node carries instruction/block semantics")
        elif self.kind is StaticBehaviorNodeKind.BASIC_BLOCK:
            if self.function_address is None or self.basic_block_address is None:
                raise ValueError("basic-block node requires function and block")
            if any(
                value is not None
                for value in (
                    self.instruction_address,
                    self.instruction_word,
                    self.instruction_size,
                    self.semantic_operation,
                )
            ) or self.semantic_attributes is not None:
                raise ValueError("basic-block node carries instruction semantics")
        else:
            required = (
                self.function_address,
                self.basic_block_address,
                self.instruction_address,
                self.instruction_word,
                self.instruction_size,
                self.semantic_operation,
            )
            if any(value is None for value in required):
                raise ValueError("semantic-fact node is missing static fact fields")
            if self.semantic_attributes is None:
                raise ValueError("semantic-fact node requires typed attributes")
        return self


class StaticBehaviorNode(_StaticBehaviorNodeBody):
    """One objective node in the binary static program graph."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticBehaviorNode":
        body = _StaticBehaviorNodeBody.model_validate(values)
        payload = body.model_dump(mode="json")
        return cls(id=static_behavior_node_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticBehaviorNode":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_behavior_node_id(payload):
            raise ValueError("static behavior node ID mismatch")
        return self


class _StaticBehaviorRelationBody(DomainModel):
    relation_kind: StaticBehaviorRelationKind
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    source_node_id: Identifier
    target_node_id: Identifier
    source_object_ids: list[Identifier] = Field(min_length=1)
    assertion_class: Literal[
        StaticAssertionClass.OBJECTIVE_STRUCTURAL_RELATION
    ]
    causal: Literal[False] = False
    runtime_execution: Literal[False] = False
    symbolic_feasibility: Literal[False] = False

    @field_validator(
        "artifact_id", "source_node_id", "target_node_id"
    )
    @classmethod
    def reject_path_identifiers(cls, value: str) -> str:
        return _reject_path_like_identifier(
            value, label="static relation identifier"
        )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("source_object_ids")
    @classmethod
    def normalize_source_objects(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("relation source-object IDs must be unique")
        return sorted(
            _reject_path_like_identifier(
                value, label="relation source-object ID"
            )
            for value in values
        )


class StaticBehaviorRelation(_StaticBehaviorRelationBody):
    """One objective, explicitly non-causal static structural relation."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticBehaviorRelation":
        body = _StaticBehaviorRelationBody.model_validate(values)
        payload = body.model_dump(mode="json")
        return cls(id=static_behavior_relation_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticBehaviorRelation":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_behavior_relation_id(payload):
            raise ValueError("static behavior relation ID mismatch")
        return self


def _node_sort_key(node: StaticBehaviorNode) -> tuple[object, ...]:
    return (
        node.kind.value,
        int(node.function_address or "0x0", 16),
        int(node.basic_block_address or "0x0", 16),
        int(node.instruction_address or "0x0", 16),
        node.id,
    )


def _relation_sort_key(
    relation: StaticBehaviorRelation,
) -> tuple[str, str, str, str]:
    return (
        relation.relation_kind.value,
        relation.source_node_id,
        relation.target_node_id,
        relation.id,
    )


def _graph_diagnostics(
    nodes: list[StaticBehaviorNode],
    relations: list[StaticBehaviorRelation],
    *,
    unprojected_nonpredicate_fact_count: int,
) -> list[str]:
    function_count = sum(
        item.kind is StaticBehaviorNodeKind.FUNCTION for item in nodes
    )
    block_count = sum(
        item.kind is StaticBehaviorNodeKind.BASIC_BLOCK for item in nodes
    )
    fact_count = sum(
        item.kind is StaticBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT
        for item in nodes
    )
    successor_count = sum(
        item.relation_kind is StaticBehaviorRelationKind.CFG_SUCCESSOR
        for item in relations
    )
    return sorted(
        [
            f"function_node_count:{function_count}",
            f"basic_block_node_count:{block_count}",
            f"semantic_fact_node_count:{fact_count}",
            f"cfg_successor_relation_count:{successor_count}",
            "unprojected_nonpredicate_fact_count:"
            f"{unprojected_nonpredicate_fact_count}",
        ]
    )


class _StaticBehaviorGraphProjectionBody(DomainModel):
    contract: Literal[PHASE10D_STATIC_BEHAVIOR_GRAPH_PROJECTION_CONTRACT]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    source_static_analysis_result_id: Identifier
    nodes: list[StaticBehaviorNode] = Field(default_factory=list)
    relations: list[StaticBehaviorRelation] = Field(default_factory=list)
    projection_scope: Literal[
        StaticBehaviorProjectionScope.BINARY_STATIC_PROGRAM_ANALYSIS
    ]
    unprojected_nonpredicate_fact_count: int = Field(ge=0)
    diagnostic_codes: list[Identifier]

    @field_validator("artifact_id", "source_static_analysis_result_id")
    @classmethod
    def reject_path_identifiers(cls, value: str) -> str:
        return _reject_path_like_identifier(
            value, label="static graph provenance identifier"
        )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("nodes")
    @classmethod
    def normalize_nodes(
        cls, values: list[StaticBehaviorNode]
    ) -> list[StaticBehaviorNode]:
        ids = [item.id for item in values]
        sources = [item.source_object_id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("static graph node IDs must be unique")
        if len(sources) != len(set(sources)):
            raise ValueError("static graph source objects project more than once")
        return sorted(values, key=_node_sort_key)

    @field_validator("relations")
    @classmethod
    def normalize_relations(
        cls, values: list[StaticBehaviorRelation]
    ) -> list[StaticBehaviorRelation]:
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("static graph relation IDs must be unique")
        return sorted(values, key=_relation_sort_key)

    @field_validator("diagnostic_codes")
    @classmethod
    def normalize_diagnostics(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("static graph diagnostics must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_graph_integrity(self) -> "_StaticBehaviorGraphProjectionBody":
        node_by_id = {item.id: item for item in self.nodes}
        function_by_address = {
            item.function_address: item
            for item in self.nodes
            if item.kind is StaticBehaviorNodeKind.FUNCTION
        }
        for node in self.nodes:
            if node.architecture is not self.architecture:
                raise ValueError("static graph node architecture mismatch")
            if (node.artifact_id, node.artifact_sha256) != (
                self.artifact_id,
                self.artifact_sha256,
            ):
                raise ValueError("static graph node artifact binding mismatch")
            if node.kind is StaticBehaviorNodeKind.BASIC_BLOCK:
                function = function_by_address.get(node.function_address)
                if function is None or node.source_object_id != (
                    _cfg_block_source_id(
                        function.source_object_id,
                        node.basic_block_address,
                    )
                ):
                    raise ValueError(
                        "basic-block node does not bind exact function CFG source"
                    )
        for relation in self.relations:
            if relation.architecture is not self.architecture:
                raise ValueError("static graph relation architecture mismatch")
            if (relation.artifact_id, relation.artifact_sha256) != (
                self.artifact_id,
                self.artifact_sha256,
            ):
                raise ValueError("static graph relation artifact binding mismatch")
            if relation.source_node_id not in node_by_id or (
                relation.target_node_id not in node_by_id
            ):
                raise ValueError("static graph relation has a dangling endpoint")
            source = node_by_id[relation.source_node_id]
            target = node_by_id[relation.target_node_id]
            if relation.relation_kind is (
                StaticBehaviorRelationKind.FUNCTION_CONTAINS_BASIC_BLOCK
            ):
                if (
                    source.kind is not StaticBehaviorNodeKind.FUNCTION
                    or target.kind is not StaticBehaviorNodeKind.BASIC_BLOCK
                    or source.function_address != target.function_address
                ):
                    raise ValueError(
                        "function-containment relation has incompatible endpoints"
                    )
                expected_sources = {
                    source.source_object_id,
                    target.source_object_id,
                }
            elif relation.relation_kind is (
                StaticBehaviorRelationKind
                .BASIC_BLOCK_CONTAINS_SEMANTIC_FACT
            ):
                if (
                    source.kind is not StaticBehaviorNodeKind.BASIC_BLOCK
                    or target.kind is not (
                        StaticBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT
                    )
                    or source.function_address != target.function_address
                    or source.basic_block_address != target.basic_block_address
                ):
                    raise ValueError(
                        "fact-containment relation has incompatible endpoints"
                    )
                function = function_by_address[source.function_address]
                expected_sources = {
                    function.source_object_id,
                    target.source_object_id,
                }
            else:
                if (
                    source.kind is not StaticBehaviorNodeKind.BASIC_BLOCK
                    or target.kind is not StaticBehaviorNodeKind.BASIC_BLOCK
                    or source.function_address != target.function_address
                ):
                    raise ValueError("CFG successor has incompatible endpoints")
                function = function_by_address[source.function_address]
                expected_sources = {
                    function.source_object_id,
                    _cfg_edge_source_id(
                        function.source_object_id,
                        source.basic_block_address,
                        target.basic_block_address,
                    ),
                }
            if set(relation.source_object_ids) != expected_sources:
                raise ValueError(
                    "static relation source provenance is not exact"
                )
        expected_diagnostics = _graph_diagnostics(
            self.nodes,
            self.relations,
            unprojected_nonpredicate_fact_count=(
                self.unprojected_nonpredicate_fact_count
            ),
        )
        if self.diagnostic_codes != expected_diagnostics:
            raise ValueError("static graph diagnostics do not match contents")
        return self


class StaticBehaviorGraphProjection(_StaticBehaviorGraphProjectionBody):
    """Objective binary facts and structural relations only."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticBehaviorGraphProjection":
        body = _StaticBehaviorGraphProjectionBody.model_validate(values)
        payload = body.model_dump(mode="json")
        return cls(id=static_behavior_graph_projection_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticBehaviorGraphProjection":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_behavior_graph_projection_id(payload):
            raise ValueError("static behavior graph projection ID mismatch")
        return self


class _StaticPatternBindingRecordBody(DomainModel):
    binding_kind: StaticPatternBindingKind
    binding_semantics: StaticPatternBindingSemantics
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    source_pattern_id: Identifier
    extraction_plan_id: Identifier
    case_id: Identifier
    source_candidate_id: Identifier | None = None
    source_fact_id: Identifier | None = None
    position_index: int | None = Field(default=None, ge=1)
    predicate_ref: Identifier | None = None
    semantic_fact_node_id: Identifier | None = None
    source_case_order_candidate_id: Identifier | None = None
    position_1_predicate_candidate_id: Identifier | None = None
    position_2_predicate_candidate_id: Identifier | None = None
    position_1_fact_node_id: Identifier | None = None
    position_2_fact_node_id: Identifier | None = None
    function_cfg_snapshot_id: Identifier | None = None
    order_basis: StaticPatternOrderBasis | None = None
    witness_basic_block_path: list[Identifier] = Field(default_factory=list)
    path_witness_use: StaticPatternPathWitnessUse | None = None
    remaining_objective_obligations: list[StaticObjectiveObligation] = Field(
        min_length=1
    )
    assertion_class: Literal[
        StaticAssertionClass.DETERMINISTIC_PATTERN_CANDIDATE
    ]

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator(
        "artifact_id",
        "source_pattern_id",
        "extraction_plan_id",
        "source_candidate_id",
        "source_fact_id",
        "predicate_ref",
        "semantic_fact_node_id",
        "source_case_order_candidate_id",
        "position_1_predicate_candidate_id",
        "position_2_predicate_candidate_id",
        "position_1_fact_node_id",
        "position_2_fact_node_id",
        "function_cfg_snapshot_id",
    )
    @classmethod
    def reject_path_identifiers(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _reject_path_like_identifier(
            value, label="static pattern-binding identifier"
        )

    @field_validator("witness_basic_block_path", mode="before")
    @classmethod
    def normalize_witness_path(cls, values: object) -> list[str]:
        if not isinstance(values, list):
            raise ValueError("static pattern witness path must be a list")
        normalized = [
            value
            for item in values
            if (value := _canonical_address(item)) is not None
        ]
        if len(normalized) != len(set(normalized)):
            raise ValueError("static pattern witness path must be cycle-free")
        return normalized

    @field_validator("remaining_objective_obligations")
    @classmethod
    def normalize_obligations(
        cls, values: list[StaticObjectiveObligation]
    ) -> list[StaticObjectiveObligation]:
        if len(values) != len(set(values)):
            raise ValueError("pattern-binding obligations must be unique")
        return sorted(values, key=lambda item: item.value)

    @model_validator(mode="after")
    def validate_binding_shape(self) -> "_StaticPatternBindingRecordBody":
        predicate_fields = (
            self.source_candidate_id,
            self.source_fact_id,
            self.position_index,
            self.predicate_ref,
            self.semantic_fact_node_id,
        )
        case_fields = (
            self.source_case_order_candidate_id,
            self.position_1_predicate_candidate_id,
            self.position_2_predicate_candidate_id,
            self.position_1_fact_node_id,
            self.position_2_fact_node_id,
            self.function_cfg_snapshot_id,
            self.order_basis,
            self.path_witness_use,
        )
        if self.binding_kind is StaticPatternBindingKind.PREDICATE_CANDIDATE:
            if self.binding_semantics is not (
                StaticPatternBindingSemantics.CANDIDATE_FOR_PATTERN_PREDICATE
            ):
                raise ValueError("predicate binding uses wrong neutral semantics")
            if any(value is None for value in predicate_fields):
                raise ValueError("predicate binding is incomplete")
            if any(value is not None for value in case_fields) or (
                self.witness_basic_block_path
            ):
                raise ValueError("predicate binding carries case-order fields")
        else:
            if self.binding_semantics is not (
                StaticPatternBindingSemantics
                .STATIC_ORDER_COMPATIBLE_PATTERN_CANDIDATE
            ):
                raise ValueError("case-order binding uses wrong neutral semantics")
            if any(value is not None for value in predicate_fields):
                raise ValueError("case-order binding carries predicate-only fields")
            if any(value is None for value in case_fields):
                raise ValueError("case-order binding is incomplete")
            if not self.witness_basic_block_path:
                raise ValueError("case-order binding requires an audit witness path")
        return self


class StaticPatternBindingRecord(_StaticPatternBindingRecordBody):
    """One deterministic candidate binding outside the program graph."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticPatternBindingRecord":
        body = _StaticPatternBindingRecordBody.model_validate(values)
        payload = body.model_dump(mode="json")
        return cls(id=static_pattern_binding_record_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticPatternBindingRecord":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_pattern_binding_record_id(payload):
            raise ValueError("static pattern-binding record ID mismatch")
        return self


def _binding_sort_key(
    record: StaticPatternBindingRecord,
) -> tuple[object, ...]:
    return (
        record.source_pattern_id,
        record.case_id,
        record.position_index or 0,
        record.source_candidate_id
        or record.source_case_order_candidate_id
        or "",
        record.id,
    )


def _pattern_diagnostics(
    records: list[StaticPatternBindingRecord],
) -> list[str]:
    predicate_count = sum(
        item.binding_kind is StaticPatternBindingKind.PREDICATE_CANDIDATE
        for item in records
    )
    case_count = sum(
        item.binding_kind is StaticPatternBindingKind.CASE_ORDER_CANDIDATE
        for item in records
    )
    return sorted(
        [
            f"predicate_candidate_binding_count:{predicate_count}",
            f"case_order_candidate_binding_count:{case_count}",
        ]
    )


class _StaticPatternBindingProjectionBody(DomainModel):
    contract: Literal[PHASE10D_STATIC_PATTERN_BINDING_PROJECTION_CONTRACT]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    source_static_analysis_result_id: Identifier
    source_case_assembly_result_id: Identifier
    source_pattern_id: Identifier
    extraction_plan_id: Identifier
    records: list[StaticPatternBindingRecord] = Field(default_factory=list)
    diagnostic_codes: list[Identifier]

    @field_validator(
        "artifact_id",
        "source_static_analysis_result_id",
        "source_case_assembly_result_id",
        "source_pattern_id",
        "extraction_plan_id",
    )
    @classmethod
    def reject_path_identifiers(cls, value: str) -> str:
        return _reject_path_like_identifier(
            value, label="pattern projection provenance identifier"
        )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("records")
    @classmethod
    def normalize_records(
        cls, values: list[StaticPatternBindingRecord]
    ) -> list[StaticPatternBindingRecord]:
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("static pattern-binding record IDs must be unique")
        source_keys = [
            (
                item.binding_kind,
                item.source_candidate_id
                or item.source_case_order_candidate_id,
            )
            for item in values
        ]
        if len(source_keys) != len(set(source_keys)):
            raise ValueError("pattern candidates must project exactly once")
        return sorted(values, key=_binding_sort_key)

    @field_validator("diagnostic_codes")
    @classmethod
    def normalize_diagnostics(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("static pattern diagnostics must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_projection_integrity(
        self,
    ) -> "_StaticPatternBindingProjectionBody":
        for record in self.records:
            if record.architecture is not self.architecture:
                raise ValueError("pattern-binding record architecture mismatch")
            if (record.artifact_id, record.artifact_sha256) != (
                self.artifact_id,
                self.artifact_sha256,
            ):
                raise ValueError("pattern-binding record artifact mismatch")
            if (
                record.source_pattern_id,
                record.extraction_plan_id,
            ) != (self.source_pattern_id, self.extraction_plan_id):
                raise ValueError("pattern-binding record source mismatch")
        if self.diagnostic_codes != _pattern_diagnostics(self.records):
            raise ValueError("static pattern diagnostics do not match contents")
        return self


class StaticPatternBindingProjection(_StaticPatternBindingProjectionBody):
    """Deterministic pattern candidates kept outside the program graph."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticPatternBindingProjection":
        body = _StaticPatternBindingProjectionBody.model_validate(values)
        payload = body.model_dump(mode="json")
        return cls(id=static_pattern_binding_projection_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticPatternBindingProjection":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_pattern_binding_projection_id(payload):
            raise ValueError("static pattern-binding projection ID mismatch")
        return self


class _StaticBehaviorAnalysisProjectionBody(DomainModel):
    contract: Literal[PHASE10D_STATIC_BEHAVIOR_ANALYSIS_PROJECTION_CONTRACT]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    source_case_assembly_result_id: Identifier
    source_case_assembly_result_snapshot: AProfileStaticCaseAssemblyResult
    program_graph: StaticBehaviorGraphProjection
    pattern_bindings: StaticPatternBindingProjection

    @field_validator("artifact_id", "source_case_assembly_result_id")
    @classmethod
    def reject_path_identifiers(cls, value: str) -> str:
        return _reject_path_like_identifier(
            value, label="analysis projection provenance identifier"
        )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @model_validator(mode="after")
    def validate_standalone_integrity(
        self,
    ) -> "_StaticBehaviorAnalysisProjectionBody":
        from chipchain.analysis.static_behavior_projection import _project_source

        source = self.source_case_assembly_result_snapshot
        if self.source_case_assembly_result_id != source.id:
            raise ValueError("analysis projection source snapshot ID mismatch")
        if (
            self.architecture,
            self.artifact_id,
            self.artifact_sha256,
        ) != (
            source.architecture,
            source.artifact_id,
            source.artifact_sha256,
        ):
            raise ValueError("analysis projection source provenance mismatch")
        expected_graph, expected_bindings = _project_source(source)
        if self.program_graph != expected_graph:
            raise ValueError("program graph differs from exact source projection")
        if self.pattern_bindings != expected_bindings:
            raise ValueError("pattern bindings differ from exact source projection")
        return self


class StaticBehaviorAnalysisProjection(
    _StaticBehaviorAnalysisProjectionBody
):
    """Standalone exact projection of one frozen static case-assembly result."""

    id: Identifier

    @classmethod
    def create(
        cls,
        *,
        source_case_assembly_result: AProfileStaticCaseAssemblyResult,
    ) -> "StaticBehaviorAnalysisProjection":
        from chipchain.analysis.static_behavior_projection import _project_source

        source = AProfileStaticCaseAssemblyResult.model_validate(
            source_case_assembly_result.model_dump(mode="json")
        )
        graph, bindings = _project_source(source)
        values = {
            "contract": PHASE10D_STATIC_BEHAVIOR_ANALYSIS_PROJECTION_CONTRACT,
            "architecture": source.architecture,
            "artifact_id": source.artifact_id,
            "artifact_sha256": source.artifact_sha256,
            "source_case_assembly_result_id": source.id,
            "source_case_assembly_result_snapshot": source,
            "program_graph": graph,
            "pattern_bindings": bindings,
        }
        body = _StaticBehaviorAnalysisProjectionBody.model_validate(values)
        payload = body.model_dump(mode="json")
        return cls(id=static_behavior_analysis_projection_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticBehaviorAnalysisProjection":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_behavior_analysis_projection_id(payload):
            raise ValueError("static behavior analysis projection ID mismatch")
        return self
