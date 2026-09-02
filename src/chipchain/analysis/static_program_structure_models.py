"""Architecture-neutral objective static program-structure contracts."""

from __future__ import annotations

from enum import Enum
import hashlib
import json
import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


PHASE10D_STATIC_PROGRAM_CFG_EDGE_CONTRACT = (
    "phase10d_static_program_cfg_edge_v1"
)
PHASE10D_STATIC_PROGRAM_FUNCTION_CFG_CONTRACT = (
    "phase10d_static_program_function_cfg_v1"
)
PHASE10D_STATIC_PROGRAM_STRUCTURE_INVENTORY_CONTRACT = (
    "phase10d_static_program_structure_inventory_v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HEX_ADDRESS = re.compile(r"^0x[0-9a-fA-F]+$")
_FORBIDDEN_OUTCOME_FRAGMENTS = (
    "attack_chain",
    "causes",
    "confidence",
    "coverage_score",
    "executed",
    "feasible",
    "triggerable",
    "verified",
    "vulnerable",
)


class StaticProgramStructureInventoryScope(str, Enum):
    """Honest completeness boundary for one structure analyzer profile."""

    PARTIAL_OBJECTIVE_FUNCTION_LOCAL_CFG_INVENTORY = (
        "partial_objective_function_local_cfg_inventory"
    )


class StaticProgramCfgSemantics(str, Enum):
    """Closed structural meaning for normalized directed block relations."""

    FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1 = (
        "function_local_directed_basic_block_reachability_v1"
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


def _canonical_address(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("static program address must be a hexadecimal string")
    candidate = value.strip()
    if not _HEX_ADDRESS.fullmatch(candidate):
        raise ValueError("static program address must use hexadecimal notation")
    return hex(int(candidate, 16))


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


def _validate_provenance_identifier(value: str, *, label: str) -> str:
    value = _reject_path_like_identifier(value, label=label)
    return _reject_outcome_like_value(value, label=label)


def static_program_cfg_edge_id(payload: object) -> str:
    """Return a deterministic directed structure-edge identity."""

    return _semantic_id("static-program-cfg-edge", payload)


def static_program_function_cfg_id(payload: object) -> str:
    """Return a deterministic function-local structure identity."""

    return _semantic_id("static-program-function-cfg", payload)


def static_program_structure_inventory_id(payload: object) -> str:
    """Return a deterministic static structure inventory identity."""

    return _semantic_id("static-program-structure-inventory", payload)


def static_program_basic_block_source_id(
    function_cfg_id: str,
    basic_block_address: str,
) -> str:
    """Return deterministic provenance for one block in one function CFG."""

    function_id = function_cfg_id.strip()
    if not function_id:
        raise ValueError("function CFG ID must not be empty")
    function_id = _validate_provenance_identifier(
        function_id, label="function CFG ID"
    )
    address = _canonical_address(basic_block_address)
    return _semantic_id(
        "static-program-basic-block-source",
        {
            "function_cfg_id": function_id,
            "basic_block_address": address,
        },
    )


class _StaticProgramCfgEdgeBody(DomainModel):
    contract: Literal["phase10d_static_program_cfg_edge_v1"]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    analyzer_profile_id: Identifier
    instruction_set: Identifier
    function_address: Identifier
    source_basic_block_address: Identifier
    target_basic_block_address: Identifier
    cfg_semantics: Literal[
        StaticProgramCfgSemantics
        .FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1
    ]
    causal: Literal[False] = False
    runtime_execution: Literal[False] = False
    symbolic_feasibility: Literal[False] = False

    @field_validator("artifact_id", "analyzer_profile_id", "instruction_set")
    @classmethod
    def validate_provenance_identifier(cls, value: str) -> str:
        return _validate_provenance_identifier(
            value, label="static program edge provenance"
        )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator(
        "function_address",
        "source_basic_block_address",
        "target_basic_block_address",
        mode="before",
    )
    @classmethod
    def normalize_address(cls, value: object) -> str:
        return _canonical_address(value)


class StaticProgramCfgEdge(_StaticProgramCfgEdgeBody):
    """One objective function-local directed basic-block relation."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticProgramCfgEdge":
        body_values = dict(values)
        body_values["contract"] = PHASE10D_STATIC_PROGRAM_CFG_EDGE_CONTRACT
        body = _StaticProgramCfgEdgeBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_program_cfg_edge_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticProgramCfgEdge":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_program_cfg_edge_id(payload):
            raise ValueError("static program CFG edge ID mismatch")
        return self


def _edge_sort_key(edge: StaticProgramCfgEdge) -> tuple[int, int, str]:
    return (
        int(edge.source_basic_block_address, 16),
        int(edge.target_basic_block_address, 16),
        edge.id,
    )


class _StaticProgramFunctionCfgBody(DomainModel):
    contract: Literal["phase10d_static_program_function_cfg_v1"]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    analyzer_profile_id: Identifier
    instruction_set: Identifier
    function_address: Identifier
    function_name: Identifier | None = None
    basic_block_addresses: list[Identifier] = Field(min_length=1)
    directed_edges: list[StaticProgramCfgEdge] = Field(default_factory=list)
    cfg_semantics: Literal[
        StaticProgramCfgSemantics
        .FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1
    ]

    @field_validator("artifact_id", "analyzer_profile_id", "instruction_set")
    @classmethod
    def validate_provenance_identifier(cls, value: str) -> str:
        return _validate_provenance_identifier(
            value, label="function CFG provenance"
        )

    @field_validator("function_name")
    @classmethod
    def validate_function_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _reject_path_like_identifier(value, label="function name")

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("function_address", mode="before")
    @classmethod
    def normalize_function_address(cls, value: object) -> str:
        return _canonical_address(value)

    @field_validator("basic_block_addresses", mode="before")
    @classmethod
    def normalize_basic_block_addresses(cls, values: object) -> list[str]:
        if not isinstance(values, list):
            raise ValueError("basic-block addresses must be a list")
        normalized = [_canonical_address(value) for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("function CFG basic-block addresses must be unique")
        return sorted(normalized, key=lambda value: int(value, 16))

    @field_validator("directed_edges")
    @classmethod
    def normalize_directed_edges(
        cls, values: list[StaticProgramCfgEdge]
    ) -> list[StaticProgramCfgEdge]:
        detached = [
            StaticProgramCfgEdge.model_validate(item.model_dump(mode="json"))
            for item in values
        ]
        ids = [item.id for item in detached]
        if len(ids) != len(set(ids)):
            raise ValueError("function CFG edge IDs must be unique")
        endpoints = [
            (
                item.source_basic_block_address,
                item.target_basic_block_address,
            )
            for item in detached
        ]
        if len(endpoints) != len(set(endpoints)):
            raise ValueError("function CFG edge endpoint pairs must be unique")
        return sorted(detached, key=_edge_sort_key)

    @model_validator(mode="after")
    def validate_function_cfg(self) -> "_StaticProgramFunctionCfgBody":
        blocks = set(self.basic_block_addresses)
        expected_provenance = (
            self.architecture,
            self.artifact_id,
            self.artifact_sha256,
            self.analyzer_profile_id,
            self.instruction_set,
            self.function_address,
            self.cfg_semantics,
        )
        for edge in self.directed_edges:
            if (
                edge.architecture,
                edge.artifact_id,
                edge.artifact_sha256,
                edge.analyzer_profile_id,
                edge.instruction_set,
                edge.function_address,
                edge.cfg_semantics,
            ) != expected_provenance:
                raise ValueError("CFG edge crosses function provenance")
            if edge.source_basic_block_address not in blocks or (
                edge.target_basic_block_address not in blocks
            ):
                raise ValueError("CFG edge endpoint is outside function blocks")
        return self


class StaticProgramFunctionCfg(_StaticProgramFunctionCfgBody):
    """One normalized objective function-local CFG snapshot."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticProgramFunctionCfg":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_PROGRAM_FUNCTION_CFG_CONTRACT
        )
        body = _StaticProgramFunctionCfgBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_program_function_cfg_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticProgramFunctionCfg":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_program_function_cfg_id(payload):
            raise ValueError("static program function CFG ID mismatch")
        return self


def _function_sort_key(item: StaticProgramFunctionCfg) -> tuple[int, str]:
    return (int(item.function_address, 16), item.id)


def static_program_structure_diagnostics(
    functions: list[StaticProgramFunctionCfg],
) -> list[str]:
    """Return exact deterministic structure inventory diagnostics."""

    return sorted(
        [
            f"function_cfg_count:{len(functions)}",
            "basic_block_count:"
            f"{sum(len(item.basic_block_addresses) for item in functions)}",
            "directed_cfg_edge_count:"
            f"{sum(len(item.directed_edges) for item in functions)}",
            "zero_edge_function_count:"
            f"{sum(not item.directed_edges for item in functions)}",
        ]
    )


class _StaticProgramStructureInventoryBody(DomainModel):
    contract: Literal["phase10d_static_program_structure_inventory_v1"]
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: Identifier
    analyzer_profile_id: Identifier
    instruction_set: Identifier
    analysis_scope: Literal[
        StaticProgramStructureInventoryScope
        .PARTIAL_OBJECTIVE_FUNCTION_LOCAL_CFG_INVENTORY
    ]
    functions: list[StaticProgramFunctionCfg] = Field(default_factory=list)
    diagnostic_codes: list[Identifier]

    @field_validator("artifact_id", "analyzer_profile_id", "instruction_set")
    @classmethod
    def validate_provenance_identifier(cls, value: str) -> str:
        return _validate_provenance_identifier(
            value, label="structure inventory provenance"
        )

    @field_validator("artifact_sha256")
    @classmethod
    def validate_artifact_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("functions")
    @classmethod
    def normalize_functions(
        cls, values: list[StaticProgramFunctionCfg]
    ) -> list[StaticProgramFunctionCfg]:
        detached = [
            StaticProgramFunctionCfg.model_validate(item.model_dump(mode="json"))
            for item in values
        ]
        ids = [item.id for item in detached]
        if len(ids) != len(set(ids)):
            raise ValueError("structure inventory function CFG IDs must be unique")
        addresses = [item.function_address for item in detached]
        if len(addresses) != len(set(addresses)):
            raise ValueError("structure inventory function addresses must be unique")
        return sorted(detached, key=_function_sort_key)

    @field_validator("diagnostic_codes")
    @classmethod
    def normalize_diagnostic_codes(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("structure inventory diagnostics must be unique")
        normalized = []
        for value in values:
            value = _reject_path_like_identifier(
                value, label="structure inventory diagnostic"
            )
            normalized.append(
                _reject_outcome_like_value(
                    value, label="structure inventory diagnostic"
                )
            )
        return sorted(normalized)

    @model_validator(mode="after")
    def validate_inventory(self) -> "_StaticProgramStructureInventoryBody":
        expected_provenance = (
            self.architecture,
            self.artifact_id,
            self.artifact_sha256,
            self.analyzer_profile_id,
            self.instruction_set,
        )
        for function in self.functions:
            if (
                function.architecture,
                function.artifact_id,
                function.artifact_sha256,
                function.analyzer_profile_id,
                function.instruction_set,
            ) != expected_provenance:
                raise ValueError("function CFG crosses structure inventory provenance")
        expected_diagnostics = static_program_structure_diagnostics(
            self.functions
        )
        if self.diagnostic_codes != expected_diagnostics:
            raise ValueError("structure inventory diagnostics do not match contents")
        return self


class StaticProgramStructureInventory(_StaticProgramStructureInventoryBody):
    """Partial objective collection of normalized function-local CFGs."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticProgramStructureInventory":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_PROGRAM_STRUCTURE_INVENTORY_CONTRACT
        )
        body_values.setdefault(
            "analysis_scope",
            (
                StaticProgramStructureInventoryScope
                .PARTIAL_OBJECTIVE_FUNCTION_LOCAL_CFG_INVENTORY
            ),
        )
        if "diagnostic_codes" not in body_values:
            raw_functions = body_values.get("functions", [])
            if not isinstance(raw_functions, list):
                raise ValueError("structure inventory functions must be a list")
            detached_functions = [
                StaticProgramFunctionCfg.model_validate(
                    item.model_dump(mode="json")
                )
                for item in raw_functions
            ]
            body_values["functions"] = detached_functions
            body_values["diagnostic_codes"] = (
                static_program_structure_diagnostics(detached_functions)
            )
        body = _StaticProgramStructureInventoryBody.model_validate(body_values)
        payload = body.model_dump(mode="json")
        return cls(id=static_program_structure_inventory_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticProgramStructureInventory":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_program_structure_inventory_id(payload):
            raise ValueError("static program structure inventory ID mismatch")
        return self
