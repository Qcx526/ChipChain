"""Deterministic contracts for neutral static trigger candidates."""

from __future__ import annotations

from enum import Enum
import hashlib
import json
import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.analysis.static_semantic_models import StaticSemanticOperation
from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


PHASE10D_STATIC_TRIGGER_POSITION_CANDIDATE_CONTRACT = (
    "phase10d_static_trigger_position_candidate_v1"
)
PHASE10D_STATIC_TRIGGER_ORDER_WITNESS_CONTRACT = (
    "phase10d_static_trigger_order_witness_v1"
)
PHASE10D_STATIC_TRIGGER_CASE_CANDIDATE_CONTRACT = (
    "phase10d_static_trigger_case_candidate_v1"
)
PHASE10D_STATIC_TRIGGER_CANDIDATE_PROJECTION_CONTRACT = (
    "phase10d_static_trigger_candidate_projection_v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HEX_ADDRESS = re.compile(r"^0x[0-9a-fA-F]+$")


class StaticTriggerCandidateSemantics(str, Enum):
    """Closed, non-outcome meaning of a v1 static candidate."""

    STATIC_STRUCTURAL_PATTERN_CANDIDATE_ONLY = (
        "static_structural_pattern_candidate_only"
    )


class StaticTriggerOrderBasis(str, Enum):
    """Objective static ordering bases admitted by the v1 matcher."""

    SAME_BASIC_BLOCK_STATIC_INSTRUCTION_ORDER = (
        "same_basic_block_static_instruction_order"
    )
    DIRECTED_FUNCTION_CFG_PATH = "directed_function_cfg_path"


class StaticTriggerPathWitnessUse(str, Enum):
    """Closed interpretation of a retained CFG path."""

    REACHABILITY_AUDIT_ONLY = "reachability_audit_only"


class StaticTriggerCandidateObjectiveObligation(str, Enum):
    """Unresolved objective work retained by a static candidate."""

    RUNTIME_EXECUTION_REQUIRED = "runtime_execution_required"
    SYMBOLIC_PATH_FEASIBILITY_REMAINS_UNRESOLVED = (
        "symbolic_path_feasibility_remains_unresolved"
    )
    EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED = (
        "effective_memory_type_resolution_required"
    )
    RUNTIME_EXECUTION_CONTEXT_REQUIRED = (
        "runtime_execution_context_required"
    )
    RELATION_PROXIMITY_REMAINS_UNRESOLVED = (
        "relation_proximity_remains_unresolved"
    )
    ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED = (
        "additional_hardware_timing_remains_unresolved"
    )


_StaticTriggerCandidateV1ObjectiveObligation = Literal[
    StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_REQUIRED,
    StaticTriggerCandidateObjectiveObligation
    .SYMBOLIC_PATH_FEASIBILITY_REMAINS_UNRESOLVED,
    StaticTriggerCandidateObjectiveObligation
    .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
    StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_CONTEXT_REQUIRED,
    StaticTriggerCandidateObjectiveObligation
    .RELATION_PROXIMITY_REMAINS_UNRESOLVED,
    StaticTriggerCandidateObjectiveObligation
    .ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED,
]

_STATIC_TRIGGER_CANDIDATE_V1_OBJECTIVE_OBLIGATIONS = (
    StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_REQUIRED,
    StaticTriggerCandidateObjectiveObligation
    .SYMBOLIC_PATH_FEASIBILITY_REMAINS_UNRESOLVED,
    StaticTriggerCandidateObjectiveObligation
    .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
    StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_CONTEXT_REQUIRED,
    StaticTriggerCandidateObjectiveObligation
    .RELATION_PROXIMITY_REMAINS_UNRESOLVED,
    StaticTriggerCandidateObjectiveObligation
    .ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED,
)


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _deterministic_id(prefix: str, payload: object) -> str:
    digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return f"{prefix}:{digest}"


def _canonical_sha256(value: str) -> str:
    candidate = value.strip()
    if not _SHA256.fullmatch(candidate):
        raise ValueError("SHA-256 must contain 64 lowercase hex digits")
    return candidate


def _canonical_address(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _HEX_ADDRESS.fullmatch(value.strip()):
        raise ValueError("candidate address must use hexadecimal notation")
    return hex(int(value.strip(), 16))


def _normalize_ids(values: list[str], *, label: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
    return sorted(values)


def static_trigger_position_candidate_id(payload: object) -> str:
    """Return one deterministic position-candidate ID."""

    return _deterministic_id("static-trigger-position-candidate", payload)


def static_trigger_order_witness_id(payload: object) -> str:
    """Return one deterministic static-order witness ID."""

    return _deterministic_id("static-trigger-order-witness", payload)


def static_trigger_case_candidate_id(payload: object) -> str:
    """Return one deterministic case-candidate ID."""

    return _deterministic_id("static-trigger-case-candidate", payload)


def static_trigger_candidate_projection_id(payload: object) -> str:
    """Return one deterministic candidate-projection ID."""

    return _deterministic_id("static-trigger-candidate-projection", payload)


class _StaticTriggerPositionCandidateBody(DomainModel):
    contract: Literal[
        "phase10d_static_trigger_position_candidate_v1"
    ]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    instruction_set: Identifier
    position_index: int = Field(ge=1)
    source_pattern_id: Identifier
    source_case_id: Identifier
    source_position_id: Identifier
    source_predicate_id: Identifier
    source_fused_fact_node_id: Identifier
    source_semantic_fact_ids: list[Identifier] = Field(
        min_length=1, max_length=1
    )
    function_address: Identifier | None = None
    basic_block_address: Identifier | None = None
    instruction_address: Identifier
    operation: StaticSemanticOperation
    candidate_semantics: Literal[
        StaticTriggerCandidateSemantics
        .STATIC_STRUCTURAL_PATTERN_CANDIDATE_ONLY
    ] = (
        StaticTriggerCandidateSemantics
        .STATIC_STRUCTURAL_PATTERN_CANDIDATE_ONLY
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

    @field_validator("source_semantic_fact_ids")
    @classmethod
    def normalize_semantic_fact_ids(cls, values: list[str]) -> list[str]:
        return _normalize_ids(values, label="semantic source fact IDs")


class StaticTriggerPositionCandidate(_StaticTriggerPositionCandidateBody):
    """One exact pattern-predicate to fused-fact static candidate binding."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticTriggerPositionCandidate":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_TRIGGER_POSITION_CANDIDATE_CONTRACT
        )
        body = _StaticTriggerPositionCandidateBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_trigger_position_candidate_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticTriggerPositionCandidate":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_trigger_position_candidate_id(payload):
            raise ValueError("static trigger position candidate ID mismatch")
        return self


class _StaticTriggerOrderWitnessBody(DomainModel):
    contract: Literal["phase10d_static_trigger_order_witness_v1"]
    from_position_index: int = Field(ge=1)
    to_position_index: int = Field(ge=2)
    source_position_candidate_id: Identifier
    target_position_candidate_id: Identifier
    order_basis: Literal[
        StaticTriggerOrderBasis.SAME_BASIC_BLOCK_STATIC_INSTRUCTION_ORDER,
        StaticTriggerOrderBasis.DIRECTED_FUNCTION_CFG_PATH,
    ]
    function_address: Identifier | None = None
    witness_basic_block_node_ids: list[Identifier] = Field(min_length=1)
    witness_cfg_relation_ids: list[Identifier] = Field(default_factory=list)
    path_witness_use: Literal[
        StaticTriggerPathWitnessUse.REACHABILITY_AUDIT_ONLY
    ] | None = None

    @field_validator("function_address", mode="before")
    @classmethod
    def normalize_function_address(cls, value: object) -> str | None:
        return _canonical_address(value)

    @model_validator(mode="after")
    def validate_order_shape(self) -> "_StaticTriggerOrderWitnessBody":
        if self.to_position_index != self.from_position_index + 1:
            raise ValueError("order witness must connect adjacent positions")
        if (
            self.source_position_candidate_id
            == self.target_position_candidate_id
        ):
            raise ValueError("order witness endpoints must be distinct")
        if len(self.witness_basic_block_node_ids) != len(
            set(self.witness_basic_block_node_ids)
        ):
            raise ValueError("order witness block path must be simple")
        if len(self.witness_cfg_relation_ids) != len(
            set(self.witness_cfg_relation_ids)
        ):
            raise ValueError("order witness CFG relation IDs must be unique")
        if self.order_basis is (
            StaticTriggerOrderBasis.SAME_BASIC_BLOCK_STATIC_INSTRUCTION_ORDER
        ):
            if len(self.witness_basic_block_node_ids) != 1:
                raise ValueError("same-block witness requires one exact block")
            if self.witness_cfg_relation_ids or self.path_witness_use is not None:
                raise ValueError("same-block witness cannot carry a CFG path")
        else:
            if len(self.witness_basic_block_node_ids) < 2:
                raise ValueError("CFG witness requires at least two blocks")
            if len(self.witness_cfg_relation_ids) != (
                len(self.witness_basic_block_node_ids) - 1
            ):
                raise ValueError("CFG witness relation count mismatch")
            if self.path_witness_use is not (
                StaticTriggerPathWitnessUse.REACHABILITY_AUDIT_ONLY
            ):
                raise ValueError("CFG path is for reachability audit only")
            if self.function_address is None:
                raise ValueError("CFG path requires a function scope")
        return self


class StaticTriggerOrderWitness(_StaticTriggerOrderWitnessBody):
    """One exact static-order witness between adjacent pattern positions."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticTriggerOrderWitness":
        body_values = dict(values)
        body_values["contract"] = PHASE10D_STATIC_TRIGGER_ORDER_WITNESS_CONTRACT
        body = _StaticTriggerOrderWitnessBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_trigger_order_witness_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticTriggerOrderWitness":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_trigger_order_witness_id(payload):
            raise ValueError("static trigger order witness ID mismatch")
        return self


def _position_candidate_sort_key(
    item: StaticTriggerPositionCandidate,
) -> tuple[object, ...]:
    return (
        item.position_index,
        item.source_predicate_id,
        item.source_fused_fact_node_id,
        item.id,
    )


def _order_witness_sort_key(
    item: StaticTriggerOrderWitness,
) -> tuple[object, ...]:
    return (item.from_position_index, item.to_position_index, item.id)


class _StaticTriggerCaseCandidateBody(DomainModel):
    contract: Literal["phase10d_static_trigger_case_candidate_v1"]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    instruction_set: Identifier
    source_pattern_id: Identifier
    source_case_id: Identifier
    case_reference_id: Identifier
    function_address: Identifier | None = None
    position_candidates: list[StaticTriggerPositionCandidate] = Field(
        min_length=1
    )
    order_witnesses: list[StaticTriggerOrderWitness] = Field(
        default_factory=list
    )
    remaining_objective_obligations: list[
        _StaticTriggerCandidateV1ObjectiveObligation
    ] = Field(min_length=1)
    candidate_semantics: Literal[
        StaticTriggerCandidateSemantics
        .STATIC_STRUCTURAL_PATTERN_CANDIDATE_ONLY
    ] = (
        StaticTriggerCandidateSemantics
        .STATIC_STRUCTURAL_PATTERN_CANDIDATE_ONLY
    )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("function_address", mode="before")
    @classmethod
    def normalize_function_address(cls, value: object) -> str | None:
        return _canonical_address(value)

    @field_validator("position_candidates")
    @classmethod
    def normalize_position_candidates(
        cls, values: list[StaticTriggerPositionCandidate]
    ) -> list[StaticTriggerPositionCandidate]:
        detached = [
            StaticTriggerPositionCandidate.model_validate(
                item.model_dump(mode="json")
            )
            for item in values
        ]
        ids = [item.id for item in detached]
        if len(ids) != len(set(ids)):
            raise ValueError("position candidate IDs must be unique")
        return sorted(detached, key=_position_candidate_sort_key)

    @field_validator("order_witnesses")
    @classmethod
    def normalize_order_witnesses(
        cls, values: list[StaticTriggerOrderWitness]
    ) -> list[StaticTriggerOrderWitness]:
        detached = [
            StaticTriggerOrderWitness.model_validate(item.model_dump(mode="json"))
            for item in values
        ]
        ids = [item.id for item in detached]
        if len(ids) != len(set(ids)):
            raise ValueError("order witness IDs must be unique")
        return sorted(detached, key=_order_witness_sort_key)

    @field_validator("remaining_objective_obligations")
    @classmethod
    def normalize_obligations(
        cls, values: list[_StaticTriggerCandidateV1ObjectiveObligation]
    ) -> list[_StaticTriggerCandidateV1ObjectiveObligation]:
        if len(values) != len(set(values)):
            raise ValueError("candidate objective obligations must be unique")
        return sorted(values, key=lambda item: item.value)

    @model_validator(mode="after")
    def validate_candidate_integrity(self) -> "_StaticTriggerCaseCandidateBody":
        positions = self.position_candidates
        indices = [item.position_index for item in positions]
        if indices != list(range(1, len(positions) + 1)):
            raise ValueError("candidate positions must be contiguous from one")
        fact_ids = [item.source_fused_fact_node_id for item in positions]
        if len(fact_ids) != len(set(fact_ids)):
            raise ValueError("one fused fact cannot satisfy two positions")
        expected_common = (
            self.architecture,
            self.artifact_id,
            self.artifact_sha256,
            self.instruction_set,
            self.source_pattern_id,
            self.source_case_id,
            self.function_address,
        )
        for item in positions:
            actual = (
                item.architecture,
                item.artifact_id,
                item.artifact_sha256,
                item.instruction_set,
                item.source_pattern_id,
                item.source_case_id,
                item.function_address,
            )
            if actual != expected_common:
                raise ValueError("position candidate provenance mismatch")
        expected_witness_pairs = {
            (index, index + 1) for index in range(1, len(positions))
        }
        actual_witness_pairs = [
            (witness.from_position_index, witness.to_position_index)
            for witness in self.order_witnesses
        ]
        if (
            len(actual_witness_pairs) != len(expected_witness_pairs)
            or set(actual_witness_pairs) != expected_witness_pairs
        ):
            raise ValueError("exact adjacent witness coverage mismatch")
        position_by_index = {item.position_index: item for item in positions}
        for witness in self.order_witnesses:
            source = position_by_index.get(witness.from_position_index)
            target = position_by_index.get(witness.to_position_index)
            if source is None or target is None:
                raise ValueError("order witness references absent position")
            if (
                witness.source_position_candidate_id != source.id
                or witness.target_position_candidate_id != target.id
                or witness.function_address != self.function_address
            ):
                raise ValueError("order witness endpoint provenance mismatch")
            if witness.order_basis is (
                StaticTriggerOrderBasis
                .SAME_BASIC_BLOCK_STATIC_INSTRUCTION_ORDER
            ):
                if source.basic_block_address is None or (
                    source.basic_block_address != target.basic_block_address
                ):
                    raise ValueError("same-block witness address mismatch")
                if int(source.instruction_address, 16) >= int(
                    target.instruction_address, 16
                ):
                    raise ValueError("same-block witness is not strict order")
            elif source.basic_block_address == target.basic_block_address:
                raise ValueError("CFG witness must cross basic blocks")
        if StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_REQUIRED not in (
            self.remaining_objective_obligations
        ):
            raise ValueError("every static candidate requires runtime execution")
        uses_cfg = any(
            witness.order_basis
            is StaticTriggerOrderBasis.DIRECTED_FUNCTION_CFG_PATH
            for witness in self.order_witnesses
        )
        has_symbolic = (
            StaticTriggerCandidateObjectiveObligation
            .SYMBOLIC_PATH_FEASIBILITY_REMAINS_UNRESOLVED
            in self.remaining_objective_obligations
        )
        if uses_cfg != has_symbolic:
            raise ValueError("CFG witness symbolic-feasibility obligation mismatch")
        return self


class StaticTriggerCaseCandidate(_StaticTriggerCaseCandidateBody):
    """One complete source-backed static structural case candidate."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticTriggerCaseCandidate":
        body_values = dict(values)
        body_values["contract"] = PHASE10D_STATIC_TRIGGER_CASE_CANDIDATE_CONTRACT
        body = _StaticTriggerCaseCandidateBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_trigger_case_candidate_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticTriggerCaseCandidate":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_trigger_case_candidate_id(payload):
            raise ValueError("static trigger case candidate ID mismatch")
        return self


def _case_candidate_sort_key(
    item: StaticTriggerCaseCandidate,
) -> tuple[object, ...]:
    return (
        item.source_pattern_id,
        item.source_case_id,
        item.function_address or "",
        tuple(position.id for position in item.position_candidates),
        item.id,
    )


def static_trigger_candidate_diagnostics(
    *,
    catalog_pattern_count: int,
    compatible_pattern_ids: list[str],
    incompatible_pattern_ids: list[str],
    case_candidates: list[StaticTriggerCaseCandidate],
) -> list[str]:
    """Return exact deterministic non-scoring candidate diagnostics."""

    positions = [
        position
        for candidate in case_candidates
        for position in candidate.position_candidates
    ]
    witnesses = [
        witness
        for candidate in case_candidates
        for witness in candidate.order_witnesses
    ]
    obligations = {
        obligation: sum(
            obligation in candidate.remaining_objective_obligations
            for candidate in case_candidates
        )
        for obligation in _STATIC_TRIGGER_CANDIDATE_V1_OBJECTIVE_OBLIGATIONS
    }
    same_block = sum(
        witness.order_basis
        is StaticTriggerOrderBasis.SAME_BASIC_BLOCK_STATIC_INSTRUCTION_ORDER
        for witness in witnesses
    )
    cfg_path = sum(
        witness.order_basis is StaticTriggerOrderBasis.DIRECTED_FUNCTION_CFG_PATH
        for witness in witnesses
    )
    memory_type_count = obligations[
        StaticTriggerCandidateObjectiveObligation
        .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
    ]
    context_count = obligations[
        StaticTriggerCandidateObjectiveObligation
        .RUNTIME_EXECUTION_CONTEXT_REQUIRED
    ]
    proximity_count = obligations[
        StaticTriggerCandidateObjectiveObligation
        .RELATION_PROXIMITY_REMAINS_UNRESOLVED
    ]
    timing_count = obligations[
        StaticTriggerCandidateObjectiveObligation
        .ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED
    ]
    symbolic_count = obligations[
        StaticTriggerCandidateObjectiveObligation
        .SYMBOLIC_PATH_FEASIBILITY_REMAINS_UNRESOLVED
    ]
    values = [
        f"catalog_pattern_count:{catalog_pattern_count}",
        f"compatible_pattern_count:{len(compatible_pattern_ids)}",
        f"incompatible_pattern_count:{len(incompatible_pattern_ids)}",
        f"case_candidate_count:{len(case_candidates)}",
        f"position_candidate_count:{len(positions)}",
        f"order_witness_count:{len(witnesses)}",
        f"same_block_order_witness_count:{same_block}",
        f"cfg_path_order_witness_count:{cfg_path}",
        "candidate_with_effective_memory_type_obligation_count:"
        f"{memory_type_count}",
        "candidate_with_execution_context_obligation_count:"
        f"{context_count}",
        "candidate_with_proximity_unresolved_count:"
        f"{proximity_count}",
        "candidate_with_additional_timing_unresolved_count:"
        f"{timing_count}",
        "candidate_with_symbolic_feasibility_unresolved_count:"
        f"{symbolic_count}",
    ]
    return sorted(values)


class _StaticTriggerCandidateProjectionBody(DomainModel):
    contract: Literal["phase10d_static_trigger_candidate_projection_v1"]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    instruction_set: Identifier
    source_fused_graph_materialization_id: Identifier
    source_fused_graph_projection_id: Identifier
    source_pattern_catalog_id: Identifier
    compatible_pattern_ids: list[Identifier] = Field(default_factory=list)
    incompatible_pattern_ids: list[Identifier] = Field(default_factory=list)
    case_candidates: list[StaticTriggerCaseCandidate] = Field(
        default_factory=list
    )
    diagnostic_codes: list[Identifier]

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("compatible_pattern_ids", "incompatible_pattern_ids")
    @classmethod
    def normalize_pattern_ids(cls, values: list[str]) -> list[str]:
        return _normalize_ids(values, label="candidate projection pattern IDs")

    @field_validator("case_candidates")
    @classmethod
    def normalize_case_candidates(
        cls, values: list[StaticTriggerCaseCandidate]
    ) -> list[StaticTriggerCaseCandidate]:
        detached = [
            StaticTriggerCaseCandidate.model_validate(item.model_dump(mode="json"))
            for item in values
        ]
        ids = [item.id for item in detached]
        if len(ids) != len(set(ids)):
            raise ValueError("case candidate IDs must be unique")
        logical = [
            (
                item.source_pattern_id,
                item.source_case_id,
                tuple(position.id for position in item.position_candidates),
            )
            for item in detached
        ]
        if len(logical) != len(set(logical)):
            raise ValueError("case candidates must be logically unique")
        return sorted(detached, key=_case_candidate_sort_key)

    @field_validator("diagnostic_codes")
    @classmethod
    def normalize_diagnostics(cls, values: list[str]) -> list[str]:
        return _normalize_ids(values, label="candidate diagnostics")

    @model_validator(mode="after")
    def validate_projection_integrity(
        self,
    ) -> "_StaticTriggerCandidateProjectionBody":
        if set(self.compatible_pattern_ids).intersection(
            self.incompatible_pattern_ids
        ):
            raise ValueError("compatible and incompatible patterns overlap")
        common = (
            self.architecture,
            self.artifact_id,
            self.artifact_sha256,
            self.instruction_set,
        )
        for candidate in self.case_candidates:
            if (
                candidate.architecture,
                candidate.artifact_id,
                candidate.artifact_sha256,
                candidate.instruction_set,
            ) != common:
                raise ValueError("case candidate projection provenance mismatch")
            if candidate.source_pattern_id not in self.compatible_pattern_ids:
                raise ValueError("case candidate uses an incompatible pattern")
        expected = static_trigger_candidate_diagnostics(
            catalog_pattern_count=(
                len(self.compatible_pattern_ids)
                + len(self.incompatible_pattern_ids)
            ),
            compatible_pattern_ids=self.compatible_pattern_ids,
            incompatible_pattern_ids=self.incompatible_pattern_ids,
            case_candidates=self.case_candidates,
        )
        if self.diagnostic_codes != expected:
            raise ValueError("candidate projection diagnostics mismatch")
        return self


class StaticTriggerCandidateProjection(
    _StaticTriggerCandidateProjectionBody
):
    """Standalone internally consistent static candidate projection."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticTriggerCandidateProjection":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_TRIGGER_CANDIDATE_PROJECTION_CONTRACT
        )
        body_values["diagnostic_codes"] = static_trigger_candidate_diagnostics(
            catalog_pattern_count=(
                len(body_values.get("compatible_pattern_ids", []))
                + len(body_values.get("incompatible_pattern_ids", []))
            ),
            compatible_pattern_ids=list(
                body_values.get("compatible_pattern_ids", [])
            ),
            incompatible_pattern_ids=list(
                body_values.get("incompatible_pattern_ids", [])
            ),
            case_candidates=list(body_values.get("case_candidates", [])),
        )
        body = _StaticTriggerCandidateProjectionBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_trigger_candidate_projection_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticTriggerCandidateProjection":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_trigger_candidate_projection_id(payload):
            raise ValueError("static trigger candidate projection ID mismatch")
        return self
