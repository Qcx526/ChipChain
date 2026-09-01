"""Pure contracts for function-local AArch64 static case-order candidates.

The models represent structural CFG order compatibility only. They do not
describe runtime execution, symbolic path feasibility, proximity, hardware
effects, triggerability, verification, or vulnerability outcomes.
"""

from __future__ import annotations

from collections import deque
from enum import Enum
import hashlib
import json
import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.hardware_trigger.a_profile_static_semantic_models import (
    AProfileStaticInstructionSetState,
    AProfileStaticPredicateCandidate,
    AProfileStaticSemanticExtractionPlan,
    AProfileStaticSemanticExtractionResult,
    AProfileStaticSemanticInstructionFact,
    RemainingObjectiveObligation,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


PHASE10D_A_PROFILE_STATIC_FUNCTION_CFG_CONTRACT = (
    "phase10d_a_profile_static_function_cfg_v1"
)
PHASE10D_A_PROFILE_STATIC_CASE_ORDER_CANDIDATE_CONTRACT = (
    "phase10d_a_profile_static_case_order_candidate_v1"
)
PHASE10D_A_PROFILE_STATIC_CASE_ASSEMBLY_RESULT_CONTRACT = (
    "phase10d_a_profile_static_case_assembly_result_v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_DIAGNOSTIC_FRAGMENTS = (
    "confidence",
    "effective_memory_type",
    "executed",
    "feasible_attack",
    "observed",
    "primary",
    "proximity_satisfied",
    "runtime_program_order",
    "satisfied",
    "score",
    "triggered",
    "triggerability",
    "verified",
    "verification",
    "vulnerability",
)


class StaticCfgScope(str, Enum):
    """The only graph scope supported by static case contract v1."""

    FUNCTION_LOCAL_MAIN_OBJECT_EXECUTABLE_CFG = (
        "function_local_main_object_executable_cfg"
    )


class StaticCfgSemantics(str, Enum):
    """Structural meaning of a normalized function CFG snapshot."""

    FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1 = (
        "function_local_directed_basic_block_reachability_v1"
    )


class StaticCaseOrderBasis(str, Enum):
    """Closed structural order-witness kinds for v1."""

    SAME_BASIC_BLOCK_INSTRUCTION_ORDER = (
        "same_basic_block_instruction_order"
    )
    DIRECTED_FUNCTION_CFG_PATH = "directed_function_cfg_path"


class StaticCaseOrderSemantics(str, Enum):
    """The strongest statement made by a static case-order candidate."""

    STATIC_CFG_ORDER_COMPATIBLE = "static_cfg_order_compatible"


class StaticPathWitnessUse(str, Enum):
    """Permitted interpretation of a persisted deterministic CFG path."""

    REACHABILITY_AUDIT_ONLY = "reachability_audit_only"


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


def _canonical_a64_address(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("A-profile CFG address must be a hexadecimal string")
    candidate = value.strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]{16}", candidate):
        raise ValueError(
            "A-profile CFG address must use 0x followed by exactly "
            "16 hexadecimal digits"
        )
    return candidate.lower()


def _reject_path_like_identifier(value: str, *, label: str) -> str:
    lowered = value.lower()
    if "/" in value or "\\" in value or lowered.startswith(("file:", "~")):
        raise ValueError(f"{label} must be path-neutral")
    return value


def _normalize_obligations(
    values: list[RemainingObjectiveObligation],
) -> list[RemainingObjectiveObligation]:
    if len(values) != len(set(values)):
        raise ValueError("remaining objective obligations must be unique")
    return sorted(values, key=lambda item: item.value)


class AProfileStaticCfgEdge(DomainModel):
    """One directed edge between normalized function-local basic blocks."""

    source_basic_block_address: Identifier
    target_basic_block_address: Identifier

    @field_validator(
        "source_basic_block_address",
        "target_basic_block_address",
        mode="before",
    )
    @classmethod
    def normalize_address(cls, value: object) -> str:
        return _canonical_a64_address(value)


def a_profile_static_function_cfg_id(payload: object) -> str:
    """Return a deterministic normalized function-CFG identity."""

    return _semantic_id("a-profile-static-function-cfg", payload)


class _AProfileStaticFunctionCfgSnapshotBody(DomainModel):
    artifact_id: Identifier
    artifact_sha256: Identifier
    extraction_result_id: Identifier
    extraction_plan_id: Identifier
    source_pattern_id: Identifier
    architecture: Literal[Architecture.ARM]
    architecture_profile: Literal["a_profile"]
    instruction_set_state: Literal[AProfileStaticInstructionSetState.AARCH64]
    function_address: Identifier
    function_name: Identifier | None = None
    scope: Literal[
        StaticCfgScope.FUNCTION_LOCAL_MAIN_OBJECT_EXECUTABLE_CFG
    ]
    basic_block_addresses: list[Identifier] = Field(min_length=1)
    directed_edges: list[AProfileStaticCfgEdge] = Field(default_factory=list)
    cfg_semantics: Literal[
        StaticCfgSemantics.FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1
    ]

    @field_validator("artifact_id")
    @classmethod
    def reject_artifact_path(cls, value: str) -> str:
        return _reject_path_like_identifier(value, label="CFG artifact ID")

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("function_address", mode="before")
    @classmethod
    def normalize_function_address(cls, value: object) -> str:
        return _canonical_a64_address(value)

    @field_validator("basic_block_addresses", mode="before")
    @classmethod
    def normalize_basic_blocks(cls, values: object) -> list[str]:
        if not isinstance(values, list):
            raise ValueError("basic-block addresses must be a list")
        normalized = [_canonical_a64_address(item) for item in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("function CFG basic-block addresses must be unique")
        return sorted(normalized, key=lambda item: int(item, 16))

    @field_validator("directed_edges")
    @classmethod
    def normalize_directed_edges(
        cls, values: list[AProfileStaticCfgEdge]
    ) -> list[AProfileStaticCfgEdge]:
        keys = [
            (
                item.source_basic_block_address,
                item.target_basic_block_address,
            )
            for item in values
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("function CFG directed edges must be unique")
        return sorted(
            values,
            key=lambda item: (
                int(item.source_basic_block_address, 16),
                int(item.target_basic_block_address, 16),
            ),
        )

    @model_validator(mode="after")
    def validate_edge_endpoints(self) -> "_AProfileStaticFunctionCfgSnapshotBody":
        nodes = set(self.basic_block_addresses)
        for edge in self.directed_edges:
            if (
                edge.source_basic_block_address not in nodes
                or edge.target_basic_block_address not in nodes
            ):
                raise ValueError(
                    "function CFG edge endpoint is outside basic-block snapshot"
                )
        return self


class AProfileStaticFunctionCfgSnapshot(
    _AProfileStaticFunctionCfgSnapshotBody
):
    """Path-neutral normalized CFG for one recovered executable function."""

    id: Identifier
    contract: Literal[PHASE10D_A_PROFILE_STATIC_FUNCTION_CFG_CONTRACT] = (
        PHASE10D_A_PROFILE_STATIC_FUNCTION_CFG_CONTRACT
    )

    @classmethod
    def create(
        cls,
        *,
        extraction_result: AProfileStaticSemanticExtractionResult,
        function_address: str,
        function_name: str | None,
        basic_block_addresses: list[str],
        directed_edges: list[AProfileStaticCfgEdge | dict[str, str]],
    ) -> "AProfileStaticFunctionCfgSnapshot":
        result = AProfileStaticSemanticExtractionResult.model_validate(
            extraction_result.model_dump(mode="json")
        )
        values = {
            "artifact_id": result.artifact_id,
            "artifact_sha256": result.artifact_sha256,
            "extraction_result_id": result.id,
            "extraction_plan_id": result.extraction_plan_id,
            "source_pattern_id": result.source_pattern_id,
            "architecture": result.architecture,
            "architecture_profile": result.architecture_profile,
            "instruction_set_state": result.instruction_set_state,
            "function_address": function_address,
            "function_name": function_name,
            "scope": StaticCfgScope.FUNCTION_LOCAL_MAIN_OBJECT_EXECUTABLE_CFG,
            "basic_block_addresses": basic_block_addresses,
            "directed_edges": directed_edges,
            "cfg_semantics": (
                StaticCfgSemantics
                .FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1
            ),
        }
        snapshot = _AProfileStaticFunctionCfgSnapshotBody.model_validate(values)
        payload = snapshot.model_dump(mode="json")
        payload["contract"] = PHASE10D_A_PROFILE_STATIC_FUNCTION_CFG_CONTRACT
        return cls(
            id=a_profile_static_function_cfg_id(payload),
            contract=PHASE10D_A_PROFILE_STATIC_FUNCTION_CFG_CONTRACT,
            **snapshot.model_dump(mode="json"),
        )

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "AProfileStaticFunctionCfgSnapshot":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != a_profile_static_function_cfg_id(payload):
            raise ValueError("static function-CFG ID mismatch")
        return self


def _deterministic_cfg_path(
    snapshot: AProfileStaticFunctionCfgSnapshot,
    source: str,
    target: str,
) -> list[str] | None:
    """Return one sorted-successor BFS path for reachability audit only."""

    if source not in snapshot.basic_block_addresses:
        raise ValueError("source basic block is outside function CFG snapshot")
    if target not in snapshot.basic_block_addresses:
        raise ValueError("target basic block is outside function CFG snapshot")
    if source == target:
        return [source]

    successors: dict[str, list[str]] = {
        address: [] for address in snapshot.basic_block_addresses
    }
    for edge in snapshot.directed_edges:
        successors[edge.source_basic_block_address].append(
            edge.target_basic_block_address
        )
    for values in successors.values():
        values.sort(key=lambda item: int(item, 16))

    parents: dict[str, str | None] = {source: None}
    queue: deque[str] = deque([source])
    while queue:
        current = queue.popleft()
        for successor in successors[current]:
            if successor in parents:
                continue
            parents[successor] = current
            if successor == target:
                path = [target]
                parent = parents[path[-1]]
                while parent is not None:
                    path.append(parent)
                    parent = parents[parent]
                return list(reversed(path))
            queue.append(successor)
    return None


class AProfileStaticCaseOrderWitness(DomainModel):
    """Deterministic structural order provenance, never proximity evidence."""

    function_cfg_snapshot_id: Identifier
    position_1_fact_id: Identifier
    position_2_fact_id: Identifier
    source_basic_block_address: Identifier
    target_basic_block_address: Identifier
    order_basis: StaticCaseOrderBasis
    witness_basic_block_path: list[Identifier] = Field(min_length=1)
    path_witness_use: Literal[StaticPathWitnessUse.REACHABILITY_AUDIT_ONLY]

    @field_validator(
        "source_basic_block_address",
        "target_basic_block_address",
        mode="before",
    )
    @classmethod
    def normalize_endpoint(cls, value: object) -> str:
        return _canonical_a64_address(value)

    @field_validator("witness_basic_block_path", mode="before")
    @classmethod
    def normalize_path(cls, values: object) -> list[str]:
        if not isinstance(values, list):
            raise ValueError("CFG witness path must be a list")
        normalized = [_canonical_a64_address(item) for item in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("CFG witness path must be cycle-free")
        return normalized


def a_profile_static_case_order_candidate_id(payload: object) -> str:
    """Return a deterministic static case-order candidate identity."""

    return _semantic_id("a-profile-static-case-order-candidate", payload)


class _AProfileStaticCaseOrderCandidateBody(DomainModel):
    artifact_id: Identifier
    artifact_sha256: Identifier
    source_extraction_result_id: Identifier
    source_extraction_result_snapshot: AProfileStaticSemanticExtractionResult
    extraction_plan_id: Identifier
    source_pattern_id: Identifier
    case_id: Identifier
    order_semantics: Literal[
        StaticCaseOrderSemantics.STATIC_CFG_ORDER_COMPATIBLE
    ]
    extraction_plan_snapshot: AProfileStaticSemanticExtractionPlan
    function_cfg_snapshot_id: Identifier
    function_cfg_snapshot: AProfileStaticFunctionCfgSnapshot
    position_1_candidate_id: Identifier
    position_2_candidate_id: Identifier
    position_1_candidate_snapshot: AProfileStaticPredicateCandidate
    position_2_candidate_snapshot: AProfileStaticPredicateCandidate
    position_1_fact_id: Identifier
    position_2_fact_id: Identifier
    position_1_fact_snapshot: AProfileStaticSemanticInstructionFact
    position_2_fact_snapshot: AProfileStaticSemanticInstructionFact
    order_witness: AProfileStaticCaseOrderWitness
    remaining_objective_obligations: list[
        RemainingObjectiveObligation
    ] = Field(min_length=3)

    @field_validator("artifact_id")
    @classmethod
    def reject_artifact_path(cls, value: str) -> str:
        return _reject_path_like_identifier(
            value, label="case-order candidate artifact ID"
        )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("remaining_objective_obligations")
    @classmethod
    def normalize_remaining_obligations(
        cls, values: list[RemainingObjectiveObligation]
    ) -> list[RemainingObjectiveObligation]:
        return _normalize_obligations(values)

    @model_validator(mode="after")
    def validate_standalone_integrity(
        self,
    ) -> "_AProfileStaticCaseOrderCandidateBody":
        extraction = self.source_extraction_result_snapshot
        plan = self.extraction_plan_snapshot
        cfg = self.function_cfg_snapshot
        candidate_1 = self.position_1_candidate_snapshot
        candidate_2 = self.position_2_candidate_snapshot
        fact_1 = self.position_1_fact_snapshot
        fact_2 = self.position_2_fact_snapshot
        witness = self.order_witness

        if self.source_extraction_result_id != extraction.id:
            raise ValueError("case-order source extraction-result ID mismatch")
        if (
            self.artifact_id,
            self.artifact_sha256,
            self.extraction_plan_id,
            self.source_pattern_id,
        ) != (
            extraction.artifact_id,
            extraction.artifact_sha256,
            extraction.extraction_plan_id,
            extraction.source_pattern_id,
        ):
            raise ValueError("case-order source extraction provenance mismatch")
        if plan != extraction.extraction_plan_snapshot:
            raise ValueError(
                "case-order extraction plan does not match source extraction result"
            )
        if self.extraction_plan_id != plan.id:
            raise ValueError("case-order candidate extraction-plan mismatch")
        if self.source_pattern_id != plan.source_pattern_id:
            raise ValueError("case-order candidate source-pattern mismatch")
        entries = {item.predicate_ref: item for item in plan.predicate_entries}
        if entries.get(candidate_1.predicate_ref) != (
            candidate_1.predicate_entry_snapshot
        ) or entries.get(candidate_2.predicate_ref) != (
            candidate_2.predicate_entry_snapshot
        ):
            raise ValueError("case-order candidate snapshot is not an exact plan entry")
        if (
            self.position_1_candidate_id != candidate_1.id
            or self.position_2_candidate_id != candidate_2.id
        ):
            raise ValueError("case-order candidate snapshot ID mismatch")
        candidate_by_id = {
            item.id: item for item in extraction.predicate_candidates
        }
        if candidate_by_id.get(self.position_1_candidate_id) != candidate_1 or (
            candidate_by_id.get(self.position_2_candidate_id) != candidate_2
        ):
            raise ValueError(
                "case-order predicate candidate is outside source extraction result"
            )
        if (
            self.position_1_fact_id != fact_1.id
            or self.position_2_fact_id != fact_2.id
        ):
            raise ValueError("case-order instruction-fact snapshot ID mismatch")
        fact_by_id = {item.id: item for item in extraction.instruction_facts}
        if fact_by_id.get(self.position_1_fact_id) != fact_1 or (
            fact_by_id.get(self.position_2_fact_id) != fact_2
        ):
            raise ValueError(
                "case-order instruction fact is outside source extraction result"
            )
        if (
            candidate_1.static_instruction_fact_id != fact_1.id
            or candidate_2.static_instruction_fact_id != fact_2.id
        ):
            raise ValueError("predicate candidate does not bind exact fact snapshot")
        if (
            candidate_1.case_id != self.case_id
            or candidate_2.case_id != self.case_id
            or candidate_1.case_id != candidate_2.case_id
        ):
            raise ValueError("case-order candidates must use the same exact case ID")
        if candidate_1.position_index != 1 or candidate_2.position_index != 2:
            raise ValueError("case-order candidates must bind exact positions 1 and 2")
        if (
            candidate_1.extraction_plan_id != plan.id
            or candidate_2.extraction_plan_id != plan.id
            or candidate_1.source_pattern_id != plan.source_pattern_id
            or candidate_2.source_pattern_id != plan.source_pattern_id
        ):
            raise ValueError("case-order predicate candidate source binding mismatch")
        if (
            fact_1.event_kind
            is not candidate_1.predicate_entry_snapshot.event_kind
            or fact_2.event_kind
            is not candidate_2.predicate_entry_snapshot.event_kind
            or fact_1.system_register
            is not candidate_1.predicate_entry_snapshot.system_register
            or fact_2.system_register
            is not candidate_2.predicate_entry_snapshot.system_register
        ):
            raise ValueError("case-order fact semantics do not match exact predicates")

        expected_binding = (
            self.artifact_id,
            self.artifact_sha256,
            self.source_extraction_result_id,
            self.extraction_plan_id,
            self.source_pattern_id,
        )
        cfg_binding = (
            cfg.artifact_id,
            cfg.artifact_sha256,
            cfg.extraction_result_id,
            cfg.extraction_plan_id,
            cfg.source_pattern_id,
        )
        if cfg_binding != expected_binding:
            raise ValueError("case-order function-CFG source binding mismatch")
        if (
            cfg.architecture,
            cfg.architecture_profile,
            cfg.instruction_set_state,
        ) != (
            extraction.architecture,
            extraction.architecture_profile,
            extraction.instruction_set_state,
        ):
            raise ValueError("case-order function-CFG architecture binding mismatch")
        if self.function_cfg_snapshot_id != cfg.id:
            raise ValueError("case-order function-CFG snapshot ID mismatch")
        for fact in (fact_1, fact_2):
            if (
                fact.artifact_id,
                fact.artifact_sha256,
                fact.architecture,
                fact.architecture_profile,
                fact.instruction_set_state,
            ) != (
                self.artifact_id,
                self.artifact_sha256,
                cfg.architecture,
                cfg.architecture_profile,
                cfg.instruction_set_state,
            ):
                raise ValueError("case-order instruction fact artifact mismatch")
        if (
            fact_1.function_address is None
            or fact_2.function_address is None
            or fact_1.function_address != fact_2.function_address
            or fact_1.function_address != cfg.function_address
        ):
            raise ValueError("case-order candidate must be function-local")
        for fact in (fact_1, fact_2):
            if (
                cfg.function_name is not None
                and fact.function_name is not None
                and fact.function_name != cfg.function_name
            ):
                raise ValueError("case-order function-name provenance mismatch")
            if fact.basic_block_address not in cfg.basic_block_addresses:
                raise ValueError(
                    "case-order fact block is outside function CFG snapshot"
                )

        expected_obligations = sorted(
            set(candidate_1.remaining_objective_obligations)
            | set(candidate_2.remaining_objective_obligations),
            key=lambda item: item.value,
        )
        if self.remaining_objective_obligations != expected_obligations:
            raise ValueError("case-order candidate dropped source obligations")

        if (
            witness.function_cfg_snapshot_id != cfg.id
            or witness.position_1_fact_id != fact_1.id
            or witness.position_2_fact_id != fact_2.id
            or witness.source_basic_block_address != fact_1.basic_block_address
            or witness.target_basic_block_address != fact_2.basic_block_address
        ):
            raise ValueError("case-order witness does not bind exact facts and CFG")
        expected_path = _deterministic_cfg_path(
            cfg,
            fact_1.basic_block_address,
            fact_2.basic_block_address,
        )
        if witness.order_basis is (
            StaticCaseOrderBasis.SAME_BASIC_BLOCK_INSTRUCTION_ORDER
        ):
            if fact_1.basic_block_address != fact_2.basic_block_address:
                raise ValueError("same-block witness binds different basic blocks")
            if int(fact_1.instruction_address, 16) >= int(
                fact_2.instruction_address, 16
            ):
                raise ValueError("same-block static instruction order is not forward")
            if expected_path != [fact_1.basic_block_address]:
                raise ValueError("same-block witness path is invalid")
        elif witness.order_basis is StaticCaseOrderBasis.DIRECTED_FUNCTION_CFG_PATH:
            if fact_1.basic_block_address == fact_2.basic_block_address:
                raise ValueError("directed-path witness cannot replace same-block order")
            if expected_path is None:
                raise ValueError("target block is not reachable from source block")
        if witness.witness_basic_block_path != expected_path:
            raise ValueError("CFG path is not the deterministic BFS witness")
        return self


class AProfileStaticCaseOrderCandidate(
    _AProfileStaticCaseOrderCandidateBody
):
    """Two exact predicates with a function-local structural order witness."""

    id: Identifier
    contract: Literal[
        PHASE10D_A_PROFILE_STATIC_CASE_ORDER_CANDIDATE_CONTRACT
    ] = PHASE10D_A_PROFILE_STATIC_CASE_ORDER_CANDIDATE_CONTRACT

    @classmethod
    def create(
        cls,
        *,
        extraction_result: AProfileStaticSemanticExtractionResult,
        function_cfg_snapshot: AProfileStaticFunctionCfgSnapshot,
        position_1_candidate: AProfileStaticPredicateCandidate,
        position_2_candidate: AProfileStaticPredicateCandidate,
        order_basis: StaticCaseOrderBasis,
    ) -> "AProfileStaticCaseOrderCandidate":
        result = AProfileStaticSemanticExtractionResult.model_validate(
            extraction_result.model_dump(mode="json")
        )
        cfg = AProfileStaticFunctionCfgSnapshot.model_validate(
            function_cfg_snapshot.model_dump(mode="json")
        )
        candidate_1 = AProfileStaticPredicateCandidate.model_validate(
            position_1_candidate.model_dump(mode="json")
        )
        candidate_2 = AProfileStaticPredicateCandidate.model_validate(
            position_2_candidate.model_dump(mode="json")
        )
        candidate_by_id = {item.id: item for item in result.predicate_candidates}
        if candidate_by_id.get(candidate_1.id) != candidate_1 or (
            candidate_by_id.get(candidate_2.id) != candidate_2
        ):
            raise ValueError("case-order candidate is outside extraction result")
        fact_by_id = {item.id: item for item in result.instruction_facts}
        fact_1 = fact_by_id.get(candidate_1.static_instruction_fact_id)
        fact_2 = fact_by_id.get(candidate_2.static_instruction_fact_id)
        if fact_1 is None or fact_2 is None:
            raise ValueError("case-order candidate fact is outside extraction result")
        path = _deterministic_cfg_path(
            cfg,
            fact_1.basic_block_address,
            fact_2.basic_block_address,
        )
        if path is None:
            raise ValueError("case-order target block is not structurally reachable")
        witness = AProfileStaticCaseOrderWitness(
            function_cfg_snapshot_id=cfg.id,
            position_1_fact_id=fact_1.id,
            position_2_fact_id=fact_2.id,
            source_basic_block_address=fact_1.basic_block_address,
            target_basic_block_address=fact_2.basic_block_address,
            order_basis=order_basis,
            witness_basic_block_path=path,
            path_witness_use=StaticPathWitnessUse.REACHABILITY_AUDIT_ONLY,
        )
        obligations = sorted(
            set(candidate_1.remaining_objective_obligations)
            | set(candidate_2.remaining_objective_obligations),
            key=lambda item: item.value,
        )
        values = {
            "artifact_id": result.artifact_id,
            "artifact_sha256": result.artifact_sha256,
            "source_extraction_result_id": result.id,
            "source_extraction_result_snapshot": result,
            "extraction_plan_id": result.extraction_plan_id,
            "source_pattern_id": result.source_pattern_id,
            "case_id": candidate_1.case_id,
            "order_semantics": (
                StaticCaseOrderSemantics.STATIC_CFG_ORDER_COMPATIBLE
            ),
            "extraction_plan_snapshot": result.extraction_plan_snapshot,
            "function_cfg_snapshot_id": cfg.id,
            "function_cfg_snapshot": cfg,
            "position_1_candidate_id": candidate_1.id,
            "position_2_candidate_id": candidate_2.id,
            "position_1_candidate_snapshot": candidate_1,
            "position_2_candidate_snapshot": candidate_2,
            "position_1_fact_id": fact_1.id,
            "position_2_fact_id": fact_2.id,
            "position_1_fact_snapshot": fact_1,
            "position_2_fact_snapshot": fact_2,
            "order_witness": witness,
            "remaining_objective_obligations": obligations,
        }
        snapshot = _AProfileStaticCaseOrderCandidateBody.model_validate(values)
        payload = snapshot.model_dump(mode="json")
        payload["contract"] = (
            PHASE10D_A_PROFILE_STATIC_CASE_ORDER_CANDIDATE_CONTRACT
        )
        return cls(
            id=a_profile_static_case_order_candidate_id(payload),
            contract=PHASE10D_A_PROFILE_STATIC_CASE_ORDER_CANDIDATE_CONTRACT,
            **snapshot.model_dump(mode="json"),
        )

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "AProfileStaticCaseOrderCandidate":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != a_profile_static_case_order_candidate_id(payload):
            raise ValueError("static case-order candidate ID mismatch")
        return self


def a_profile_static_case_assembly_result_id(payload: object) -> str:
    """Return a deterministic static case-assembly result identity."""

    return _semantic_id("a-profile-static-case-assembly-result", payload)


def _assembly_diagnostics(
    cfg_snapshots: list[AProfileStaticFunctionCfgSnapshot],
    candidates: list[AProfileStaticCaseOrderCandidate],
) -> list[str]:
    same_block_count = sum(
        item.order_witness.order_basis
        is StaticCaseOrderBasis.SAME_BASIC_BLOCK_INSTRUCTION_ORDER
        for item in candidates
    )
    directed_count = sum(
        item.order_witness.order_basis
        is StaticCaseOrderBasis.DIRECTED_FUNCTION_CFG_PATH
        for item in candidates
    )
    return sorted(
        [
            f"function_cfg_snapshot_count:{len(cfg_snapshots)}",
            f"static_case_order_candidate_count:{len(candidates)}",
            f"same_block_order_candidate_count:{same_block_count}",
            f"directed_cfg_order_candidate_count:{directed_count}",
        ]
    )


class _AProfileStaticCaseAssemblyResultBody(DomainModel):
    artifact_id: Identifier
    artifact_sha256: Identifier
    architecture: Literal[Architecture.ARM]
    architecture_profile: Literal["a_profile"]
    instruction_set_state: Literal[AProfileStaticInstructionSetState.AARCH64]
    source_extraction_result_id: Identifier
    extraction_plan_id: Identifier
    source_pattern_id: Identifier
    source_extraction_result_snapshot: AProfileStaticSemanticExtractionResult
    function_cfg_snapshots: list[AProfileStaticFunctionCfgSnapshot] = Field(
        default_factory=list
    )
    case_order_candidates: list[AProfileStaticCaseOrderCandidate] = Field(
        default_factory=list
    )
    diagnostic_codes: list[Identifier]

    @field_validator("artifact_id")
    @classmethod
    def reject_artifact_path(cls, value: str) -> str:
        return _reject_path_like_identifier(
            value, label="case-assembly result artifact ID"
        )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("function_cfg_snapshots")
    @classmethod
    def normalize_cfg_snapshots(
        cls, values: list[AProfileStaticFunctionCfgSnapshot]
    ) -> list[AProfileStaticFunctionCfgSnapshot]:
        ids = [item.id for item in values]
        functions = [item.function_address for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("function CFG snapshots must have unique IDs")
        if len(functions) != len(set(functions)):
            raise ValueError("function CFG snapshots must use unique functions")
        return sorted(
            values,
            key=lambda item: (int(item.function_address, 16), item.id),
        )

    @field_validator("case_order_candidates")
    @classmethod
    def normalize_case_order_candidates(
        cls, values: list[AProfileStaticCaseOrderCandidate]
    ) -> list[AProfileStaticCaseOrderCandidate]:
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("static case-order candidates must have unique IDs")
        return sorted(
            values,
            key=lambda item: (
                item.case_id,
                item.position_1_candidate_id,
                item.position_2_candidate_id,
                item.id,
            ),
        )

    @field_validator("diagnostic_codes")
    @classmethod
    def normalize_diagnostics(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("static case diagnostics must be unique")
        for value in values:
            lowered = value.lower()
            if any(item in lowered for item in _FORBIDDEN_DIAGNOSTIC_FRAGMENTS):
                raise ValueError("static case diagnostic contains an outcome")
        return sorted(values)

    @model_validator(mode="after")
    def validate_cross_bindings(
        self,
    ) -> "_AProfileStaticCaseAssemblyResultBody":
        extraction = self.source_extraction_result_snapshot
        expected_binding = (
            extraction.artifact_id,
            extraction.artifact_sha256,
            extraction.architecture,
            extraction.architecture_profile,
            extraction.instruction_set_state,
            extraction.id,
            extraction.extraction_plan_id,
            extraction.source_pattern_id,
        )
        actual_binding = (
            self.artifact_id,
            self.artifact_sha256,
            self.architecture,
            self.architecture_profile,
            self.instruction_set_state,
            self.source_extraction_result_id,
            self.extraction_plan_id,
            self.source_pattern_id,
        )
        if actual_binding != expected_binding:
            raise ValueError("static case result extraction binding mismatch")

        cfg_by_id = {item.id: item for item in self.function_cfg_snapshots}
        candidate_by_id = {
            item.id: item for item in extraction.predicate_candidates
        }
        fact_by_id = {item.id: item for item in extraction.instruction_facts}
        for cfg in self.function_cfg_snapshots:
            if (
                cfg.artifact_id,
                cfg.artifact_sha256,
                cfg.extraction_result_id,
                cfg.extraction_plan_id,
                cfg.source_pattern_id,
                cfg.architecture,
                cfg.architecture_profile,
                cfg.instruction_set_state,
            ) != (
                self.artifact_id,
                self.artifact_sha256,
                self.source_extraction_result_id,
                self.extraction_plan_id,
                self.source_pattern_id,
                self.architecture,
                self.architecture_profile,
                self.instruction_set_state,
            ):
                raise ValueError("function CFG snapshot crosses result binding")
        for candidate in self.case_order_candidates:
            if candidate.source_extraction_result_snapshot != extraction:
                raise ValueError(
                    "case-order candidate extraction snapshot differs from assembly"
                )
            if (
                candidate.artifact_id,
                candidate.artifact_sha256,
                candidate.source_extraction_result_id,
                candidate.extraction_plan_id,
                candidate.source_pattern_id,
            ) != (
                self.artifact_id,
                self.artifact_sha256,
                self.source_extraction_result_id,
                self.extraction_plan_id,
                self.source_pattern_id,
            ):
                raise ValueError("case-order candidate crosses result binding")
            if cfg_by_id.get(candidate.function_cfg_snapshot_id) != (
                candidate.function_cfg_snapshot
            ):
                raise ValueError("case-order candidate CFG is outside assembly")
            if candidate_by_id.get(candidate.position_1_candidate_id) != (
                candidate.position_1_candidate_snapshot
            ) or candidate_by_id.get(candidate.position_2_candidate_id) != (
                candidate.position_2_candidate_snapshot
            ):
                raise ValueError("case-order source candidate is outside extraction")
            if fact_by_id.get(candidate.position_1_fact_id) != (
                candidate.position_1_fact_snapshot
            ) or fact_by_id.get(candidate.position_2_fact_id) != (
                candidate.position_2_fact_snapshot
            ):
                raise ValueError("case-order source fact is outside extraction")
        if self.diagnostic_codes != _assembly_diagnostics(
            self.function_cfg_snapshots,
            self.case_order_candidates,
        ):
            raise ValueError("static case diagnostics do not match exact contents")
        return self


class AProfileStaticCaseAssemblyResult(
    _AProfileStaticCaseAssemblyResultBody
):
    """Deterministic C1 output with no runtime or verdict semantics."""

    id: Identifier
    contract: Literal[
        PHASE10D_A_PROFILE_STATIC_CASE_ASSEMBLY_RESULT_CONTRACT
    ] = PHASE10D_A_PROFILE_STATIC_CASE_ASSEMBLY_RESULT_CONTRACT

    @classmethod
    def create(
        cls,
        *,
        extraction_result: AProfileStaticSemanticExtractionResult,
        function_cfg_snapshots: list[AProfileStaticFunctionCfgSnapshot],
        case_order_candidates: list[AProfileStaticCaseOrderCandidate],
    ) -> "AProfileStaticCaseAssemblyResult":
        extraction = AProfileStaticSemanticExtractionResult.model_validate(
            extraction_result.model_dump(mode="json")
        )
        values = {
            "artifact_id": extraction.artifact_id,
            "artifact_sha256": extraction.artifact_sha256,
            "architecture": extraction.architecture,
            "architecture_profile": extraction.architecture_profile,
            "instruction_set_state": extraction.instruction_set_state,
            "source_extraction_result_id": extraction.id,
            "extraction_plan_id": extraction.extraction_plan_id,
            "source_pattern_id": extraction.source_pattern_id,
            "source_extraction_result_snapshot": extraction,
            "function_cfg_snapshots": function_cfg_snapshots,
            "case_order_candidates": case_order_candidates,
            "diagnostic_codes": _assembly_diagnostics(
                function_cfg_snapshots,
                case_order_candidates,
            ),
        }
        snapshot = _AProfileStaticCaseAssemblyResultBody.model_validate(values)
        payload = snapshot.model_dump(mode="json")
        payload["contract"] = (
            PHASE10D_A_PROFILE_STATIC_CASE_ASSEMBLY_RESULT_CONTRACT
        )
        return cls(
            id=a_profile_static_case_assembly_result_id(payload),
            contract=PHASE10D_A_PROFILE_STATIC_CASE_ASSEMBLY_RESULT_CONTRACT,
            **snapshot.model_dump(mode="json"),
        )

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "AProfileStaticCaseAssemblyResult":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != a_profile_static_case_assembly_result_id(payload):
            raise ValueError("static case-assembly result ID mismatch")
        return self
