"""Independent typed state sources; declared hashes are not raw-file verification.

The normalized materialization is authoritative (option A). Changing a normalized
value and recomputing its IDs produces a different source claim, not an attack
that this layer can detect without independent source bytes/authentication.
Instruction addresses associate records with code; they do not assert execution.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Annotated, Literal, TypeAlias, TypeVar

from pydantic import Field, StringConstraints, field_validator, model_validator

from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture
from chipchain.verification.models import ProgramAddress


PHASE10D_CANDIDATE_STATE_SOURCE_MANIFEST_CONTRACT = "phase10d_candidate_state_observation_source_manifest_v1"
PHASE10D_CANDIDATE_MEMORY_TYPE_OBSERVATION_CONTRACT = "phase10d_candidate_effective_memory_type_observation_v1"
PHASE10D_CANDIDATE_EXECUTION_CONTEXT_OBSERVATION_CONTRACT = "phase10d_candidate_execution_context_observation_v1"
PHASE10D_CANDIDATE_STATE_MATERIALIZATION_CONTRACT = "phase10d_candidate_state_observation_materialization_v1"

_STABLE_SOURCE_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_SOURCE_RECORD_LOCATOR_PATTERN = r"^record:[a-z0-9][a-z0-9._-]{0,127}$"
_STABLE_SOURCE_IDENTIFIER = re.compile(_STABLE_SOURCE_IDENTIFIER_PATTERN)
_SOURCE_RECORD_LOCATOR = re.compile(_SOURCE_RECORD_LOCATOR_PATTERN)

CandidateStateStableSourceIdentifierV1: TypeAlias = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=256,
        pattern=_STABLE_SOURCE_IDENTIFIER_PATTERN,
    ),
]
"""Stable caller/producer semantic ID; no host path or generated random/time ID."""

CandidateStateSourceRecordLocatorV1: TypeAlias = Annotated[
    str,
    StringConstraints(
        min_length=8,
        max_length=135,
        pattern=_SOURCE_RECORD_LOCATOR_PATTERN,
    ),
]
"""Canonical family-scoped logical record identity inside a source artifact."""


def _validate_stable_source_identifier(value: object) -> str:
    if (
        not isinstance(value, str)
        or _STABLE_SOURCE_IDENTIFIER.fullmatch(value) is None
        or re.match(r"^[A-Za-z]:", value) is not None
        or value.lower().startswith("file:")
    ):
        raise ValueError(
            "source semantic identifier must be stable and path/whitespace free"
        )
    return value


def candidate_state_observation_id(prefix: str, payload: object) -> str:
    """Hash canonical JSON semantic/provenance fields, including the contract."""

    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(encoded).hexdigest()}"


_T = TypeVar("_T", bound=DomainModel)


def _create(model: type[_T], body: DomainModel, prefix: str) -> _T:
    payload = body.model_dump(mode="json")
    return model.model_validate({**payload, "id": candidate_state_observation_id(prefix, payload)})


def _check_id(model: DomainModel, identifier: str, prefix: str) -> None:
    if identifier != candidate_state_observation_id(prefix, model.model_dump(mode="json", exclude={"id"})):
        raise ValueError("state source ID is not deterministic")


class CandidateStateOwnedFixtureProvenance(DomainModel):
    """Exact synthetic provenance, never a real measurement declaration."""

    owned: Literal[True]
    synthetic: Literal[True]
    fixture: Literal[True]
    not_real_vulnerability: Literal[True]
    not_benchmark: Literal[True]

    @field_validator("*", mode="before")
    @classmethod
    def exact_bool(cls, value: object) -> object:
        if value is not True:
            raise ValueError("owned fixture flags must be exactly true")
        return value


class CandidateStateAccessAddress(DomainModel):
    """Canonical addressed-location value; it does not prove an instruction access."""

    value: Identifier

    @field_validator("value", mode="before")
    @classmethod
    def normalize(cls, value: object) -> str:
        if not isinstance(value, str) or not re.fullmatch(r"0[xX][0-9a-fA-F]+", value.strip()):
            raise ValueError("access address must be hexadecimal")
        return hex(int(value, 16))


class _ArtifactProvenance(DomainModel):
    architecture: Architecture
    artifact_id: Identifier
    artifact_sha256: str
    instruction_set: Identifier

    @field_validator("artifact_sha256")
    @classmethod
    def validate_sha(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("SHA-256 must be exactly 64 lowercase hexadecimal digits")
        return value


class _SourceManifestBody(_ArtifactProvenance):
    contract: Literal["phase10d_candidate_state_observation_source_manifest_v1"]
    source_kind: Literal["owned_fixture", "external_typed_observation"]
    producer_profile_id: CandidateStateStableSourceIdentifierV1
    producer_profile_version: CandidateStateStableSourceIdentifierV1
    normalization_profile_id: CandidateStateStableSourceIdentifierV1
    source_artifact_id: CandidateStateStableSourceIdentifierV1
    source_artifact_sha256: str
    source_semantics: Literal["objective_typed_source_only"] = "objective_typed_source_only"
    owned_fixture_provenance: CandidateStateOwnedFixtureProvenance | None = None

    @field_validator(
        "source_artifact_id",
        "producer_profile_id",
        "producer_profile_version",
        "normalization_profile_id",
        mode="before",
    )
    @classmethod
    def validate_stable_source_identifier(cls, value: object) -> str:
        return _validate_stable_source_identifier(value)

    @field_validator("source_artifact_sha256")
    @classmethod
    def validate_source_sha(cls, value: str) -> str:
        return cls.validate_sha(value)

    @field_validator("owned_fixture_provenance")
    @classmethod
    def detach_flags(cls, value: CandidateStateOwnedFixtureProvenance | None) -> CandidateStateOwnedFixtureProvenance | None:
        return None if value is None else CandidateStateOwnedFixtureProvenance.model_validate(value.model_dump(mode="json"))

    @model_validator(mode="after")
    def validate_source_kind(self) -> "_SourceManifestBody":
        if (self.source_kind == "owned_fixture") != (self.owned_fixture_provenance is not None):
            raise ValueError("owned fixture provenance must occur exactly for owned_fixture")
        return self


class CandidateStateObservationSourceManifest(_SourceManifestBody):
    """Producer-declared source provenance, not producer trust or raw-byte proof."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "CandidateStateObservationSourceManifest":
        body = _SourceManifestBody.model_validate({"contract": PHASE10D_CANDIDATE_STATE_SOURCE_MANIFEST_CONTRACT, **values})
        return _create(cls, body, "candidate-state-source-manifest")

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateStateObservationSourceManifest":
        _check_id(self, self.id, "candidate-state-source-manifest")
        return self


class _ObservationBody(_ArtifactProvenance):
    source_manifest_id: Identifier
    source_record_locator: CandidateStateSourceRecordLocatorV1
    instruction_address: ProgramAddress = Field(
        description=(
            "Producer-associated program location, not an executed PC or proof "
            "of a memory-access instruction."
        )
    )
    observation_semantics: Literal["objective_source_observation_only"] = "objective_source_observation_only"

    @field_validator("instruction_address", mode="before")
    @classmethod
    def detach_address(cls, value: object) -> object:
        if isinstance(value, ProgramAddress):
            return value.model_dump(mode="json")
        if isinstance(value, str):
            return {"value": value}
        return value

    @field_validator("source_record_locator", mode="before")
    @classmethod
    def validate_source_record_locator(cls, value: object) -> str:
        if not isinstance(value, str) or _SOURCE_RECORD_LOCATOR.fullmatch(value) is None:
            raise ValueError(
                "source record locator must use canonical record:<lowercase-token> syntax"
            )
        return value


class _MemoryTypeBody(_ObservationBody):
    contract: Literal["phase10d_candidate_effective_memory_type_observation_v1"]
    access_address: CandidateStateAccessAddress = Field(
        description=(
            "Addressed-location state associated with the typed source record; "
            "it does not prove instruction_address accessed this location."
        )
    )
    access_address_kind: Literal["virtual_address", "physical_address"]
    observed_effective_memory_type_id: CandidateStateStableSourceIdentifierV1
    resolution_basis: Literal[
        "direct_typed_source", "audited_translation_resolution"
    ] = Field(
        description=(
            "Producer-profile-declared normalization basis. "
            "audited_translation_resolution means the producer declares its "
            "profile deterministically resolved lower-level translation/memory "
            "attributes; it is not independent ChipChain translation verification."
        )
    )

    @field_validator("access_address", mode="before")
    @classmethod
    def detach_access_address(cls, value: object) -> object:
        if isinstance(value, CandidateStateAccessAddress):
            return value.model_dump(mode="json")
        return value

    @field_validator("observed_effective_memory_type_id", mode="before")
    @classmethod
    def validate_memory_type_identifier(cls, value: object) -> str:
        return _validate_stable_source_identifier(value)


class CandidateEffectiveMemoryTypeObservation(_MemoryTypeBody):
    """A producer-associated normalized addressed-location memory-state record.

    The program location and addressed-location state are source associations.
    They do not assert that the instruction executed, performed this memory
    access, or satisfied any requirement. No static/runtime fallback is used.
    """

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "CandidateEffectiveMemoryTypeObservation":
        body = _MemoryTypeBody.model_validate({"contract": PHASE10D_CANDIDATE_MEMORY_TYPE_OBSERVATION_CONTRACT, **values})
        return _create(cls, body, "candidate-effective-memory-type-observation")

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateEffectiveMemoryTypeObservation":
        _check_id(self, self.id, "candidate-effective-memory-type-observation")
        return self


class _ExecutionContextBody(_ObservationBody):
    contract: Literal["phase10d_candidate_execution_context_observation_v1"]
    observed_execution_context_ids: list[
        CandidateStateStableSourceIdentifierV1
    ] = Field(min_length=1)

    @field_validator("observed_execution_context_ids", mode="before")
    @classmethod
    def validate_context_identifiers(cls, values: object) -> object:
        if isinstance(values, list):
            return [_validate_stable_source_identifier(value) for value in values]
        return values

    @field_validator("observed_execution_context_ids")
    @classmethod
    def normalize_contexts(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("execution context IDs must be unique")
        return sorted(values)


class CandidateExecutionContextObservation(_ExecutionContextBody):
    """Producer-associated normalized context facts at a source/program location.

    The record does not assert instruction execution, infer privilege/security
    state from instruction names, or satisfy any requirement.
    """

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "CandidateExecutionContextObservation":
        body = _ExecutionContextBody.model_validate({"contract": PHASE10D_CANDIDATE_EXECUTION_CONTEXT_OBSERVATION_CONTRACT, **values})
        return _create(cls, body, "candidate-execution-context-observation")

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateExecutionContextObservation":
        _check_id(self, self.id, "candidate-execution-context-observation")
        return self


class _MaterializationBody(DomainModel):
    contract: Literal["phase10d_candidate_state_observation_materialization_v1"]
    source_manifest_snapshot: CandidateStateObservationSourceManifest
    effective_memory_type_observations: list[CandidateEffectiveMemoryTypeObservation] = Field(default_factory=list)
    execution_context_observations: list[CandidateExecutionContextObservation] = Field(default_factory=list)

    @field_validator("source_manifest_snapshot")
    @classmethod
    def detach_manifest(cls, value: CandidateStateObservationSourceManifest) -> CandidateStateObservationSourceManifest:
        return CandidateStateObservationSourceManifest.model_validate(value.model_dump(mode="json"))

    @field_validator("effective_memory_type_observations")
    @classmethod
    def detach_memory(cls, values: list[CandidateEffectiveMemoryTypeObservation]) -> list[CandidateEffectiveMemoryTypeObservation]:
        return sorted((CandidateEffectiveMemoryTypeObservation.model_validate(v.model_dump(mode="json")) for v in values), key=lambda v: v.id)

    @field_validator("execution_context_observations")
    @classmethod
    def detach_context(cls, values: list[CandidateExecutionContextObservation]) -> list[CandidateExecutionContextObservation]:
        return sorted((CandidateExecutionContextObservation.model_validate(v.model_dump(mode="json")) for v in values), key=lambda v: v.id)

    @model_validator(mode="after")
    def validate_integrity(self) -> "_MaterializationBody":
        manifest = self.source_manifest_snapshot
        observations = [*self.effective_memory_type_observations, *self.execution_context_observations]
        if len({v.id for v in observations}) != len(observations):
            raise ValueError("duplicate state observation ID")
        memory_record_keys = {
            (v.source_manifest_id, v.source_record_locator)
            for v in self.effective_memory_type_observations
        }
        if len(memory_record_keys) != len(self.effective_memory_type_observations):
            raise ValueError("duplicate logical memory source record")
        context_record_keys = {
            (v.source_manifest_id, v.source_record_locator)
            for v in self.execution_context_observations
        }
        if len(context_record_keys) != len(self.execution_context_observations):
            raise ValueError("duplicate logical context source record")
        for observation in observations:
            if observation.source_manifest_id != manifest.id:
                raise ValueError("observation source manifest mismatch")
            fields = ("architecture", "artifact_id", "artifact_sha256", "instruction_set")
            if any(getattr(observation, field) != getattr(manifest, field) for field in fields):
                raise ValueError("observation artifact provenance mismatch")
        return self


class CandidateStateObservationMaterialization(_MaterializationBody):
    """Authoritative normalized source with detached, family-scoped source records.

An external source SHA is a declaration, not independent raw-file validation.
This layer checks internal provenance, not the truth of producer-supplied values.
"""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "CandidateStateObservationMaterialization":
        body = _MaterializationBody.model_validate({"contract": PHASE10D_CANDIDATE_STATE_MATERIALIZATION_CONTRACT, **values})
        return _create(cls, body, "candidate-state-observation-materialization")

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateStateObservationMaterialization":
        _check_id(self, self.id, "candidate-state-observation-materialization")
        return self


__all__ = [
    "CandidateStateAccessAddress", "CandidateStateOwnedFixtureProvenance",
    "CandidateStateStableSourceIdentifierV1", "CandidateStateSourceRecordLocatorV1",
    "CandidateStateObservationSourceManifest", "CandidateEffectiveMemoryTypeObservation",
    "CandidateExecutionContextObservation", "CandidateStateObservationMaterialization",
    "candidate_state_observation_id",
]
