"""Source-backed, outcome-neutral hardware-reference contracts."""

from __future__ import annotations

from enum import Enum
import hashlib
import json
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.hardware_trigger.documented_erratum_models import (
    DocumentedHardwareErratumContract,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


PHASE10D_STATIC_OWNED_SYNTHETIC_HARDWARE_REFERENCE_CONTRACT = (
    "phase10d_static_owned_synthetic_hardware_reference_v1"
)
PHASE10D_STATIC_DOCUMENTED_ERRATUM_HARDWARE_REFERENCE_CONTRACT = (
    "phase10d_static_documented_erratum_hardware_reference_v1"
)
PHASE10D_STATIC_HARDWARE_REFERENCE_CATALOG_CONTRACT = (
    "phase10d_static_hardware_reference_catalog_v1"
)


class StaticHardwareReferenceKind(str, Enum):
    """Closed kinds accepted by the v1 static reference catalog."""

    OWNED_SYNTHETIC_CONDITION = "owned_synthetic_condition"
    DOCUMENTED_HARDWARE_ERRATUM = "documented_hardware_erratum"


class StaticHardwareReferenceSemantics(str, Enum):
    """Closed, non-verdict meanings for source-backed references."""

    REFERENCE_ONLY = "reference_only"
    SOURCE_DOCUMENTED_REFERENCE_ONLY = "source_documented_reference_only"


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _deterministic_id(prefix: str, payload: object) -> str:
    return f"{prefix}:{hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()}"


def _path_neutral(value: str, *, label: str) -> str:
    lowered = value.lower()
    if "/" in value or "\\" in value or lowered.startswith(("file:", "~")):
        raise ValueError(f"{label} must be path-neutral")
    return value


def static_owned_synthetic_hardware_reference_id(payload: object) -> str:
    """Return the deterministic identity of one owned reference."""

    return _deterministic_id("static-owned-hardware-reference", payload)


def static_documented_erratum_hardware_reference_id(payload: object) -> str:
    """Return the deterministic identity of one documented reference wrapper."""

    return _deterministic_id("static-documented-hardware-reference", payload)


def static_hardware_reference_catalog_id(payload: object) -> str:
    """Return the deterministic identity of one reference catalog."""

    return _deterministic_id("static-hardware-reference-catalog", payload)


class _StaticOwnedSyntheticHardwareReferenceBody(DomainModel):
    contract: Literal[
        "phase10d_static_owned_synthetic_hardware_reference_v1"
    ]
    reference_id: Identifier
    architecture: Architecture
    title: Identifier
    reference_kind: Literal[
        StaticHardwareReferenceKind.OWNED_SYNTHETIC_CONDITION
    ] = StaticHardwareReferenceKind.OWNED_SYNTHETIC_CONDITION
    reference_semantics: Literal[
        StaticHardwareReferenceSemantics.REFERENCE_ONLY
    ] = StaticHardwareReferenceSemantics.REFERENCE_ONLY
    owned: Literal[True] = True
    synthetic: Literal[True] = True
    benign: Literal[True] = True
    source_reference_ids: list[Identifier] = Field(min_length=1)

    @field_validator("reference_id", "title")
    @classmethod
    def validate_path_neutral_text(cls, value: str) -> str:
        return _path_neutral(value, label="owned hardware reference text")

    @field_validator("source_reference_ids")
    @classmethod
    def normalize_source_references(cls, values: list[str]) -> list[str]:
        normalized = [
            _path_neutral(value, label="owned hardware source reference")
            for value in values
        ]
        if len(normalized) != len(set(normalized)):
            raise ValueError("owned hardware source references must be unique")
        return sorted(normalized)


class StaticOwnedSyntheticHardwareReference(
    _StaticOwnedSyntheticHardwareReferenceBody
):
    """One owned, synthetic, benign hardware-side reference only."""

    id: Identifier

    @classmethod
    def create(cls, **values: object) -> "StaticOwnedSyntheticHardwareReference":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_OWNED_SYNTHETIC_HARDWARE_REFERENCE_CONTRACT
        )
        body = _StaticOwnedSyntheticHardwareReferenceBody.model_validate(
            body_values
        )
        payload = body.model_dump(mode="json")
        return cls(
            id=static_owned_synthetic_hardware_reference_id(payload), **payload
        )

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticOwnedSyntheticHardwareReference":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_owned_synthetic_hardware_reference_id(payload):
            raise ValueError("owned synthetic hardware reference ID mismatch")
        return self


class _StaticDocumentedErratumHardwareReferenceBody(DomainModel):
    contract: Literal[
        "phase10d_static_documented_erratum_hardware_reference_v1"
    ]
    reference_id: Identifier
    architecture: Literal[Architecture.ARM]
    reference_kind: Literal[
        StaticHardwareReferenceKind.DOCUMENTED_HARDWARE_ERRATUM
    ] = StaticHardwareReferenceKind.DOCUMENTED_HARDWARE_ERRATUM
    reference_semantics: Literal[
        StaticHardwareReferenceSemantics.SOURCE_DOCUMENTED_REFERENCE_ONLY
    ] = StaticHardwareReferenceSemantics.SOURCE_DOCUMENTED_REFERENCE_ONLY
    source_documented_erratum_snapshot: DocumentedHardwareErratumContract

    @field_validator("source_documented_erratum_snapshot")
    @classmethod
    def detach_documented_erratum(
        cls, value: DocumentedHardwareErratumContract
    ) -> DocumentedHardwareErratumContract:
        return DocumentedHardwareErratumContract.model_validate(
            value.model_dump(mode="json")
        )

    @model_validator(mode="after")
    def validate_exact_reference(
        self,
    ) -> "_StaticDocumentedErratumHardwareReferenceBody":
        source = self.source_documented_erratum_snapshot
        if self.reference_id != source.id:
            raise ValueError("documented reference ID must equal erratum object ID")
        if self.architecture is not source.architecture:
            raise ValueError("documented reference architecture mismatch")
        return self


class StaticDocumentedErratumHardwareReference(
    _StaticDocumentedErratumHardwareReferenceBody
):
    """Detached wrapper around the authoritative documented erratum contract."""

    id: Identifier

    @property
    def cve_id(self) -> str:
        return self.source_documented_erratum_snapshot.cve_id

    @property
    def erratum_id(self) -> str:
        return self.source_documented_erratum_snapshot.authoritative_source.erratum_id

    @property
    def processor(self) -> str:
        return self.source_documented_erratum_snapshot.processor

    @classmethod
    def create(
        cls, **values: object
    ) -> "StaticDocumentedErratumHardwareReference":
        body_values = dict(values)
        body_values["contract"] = (
            PHASE10D_STATIC_DOCUMENTED_ERRATUM_HARDWARE_REFERENCE_CONTRACT
        )
        body = _StaticDocumentedErratumHardwareReferenceBody.model_validate(
            body_values
        )
        payload = body.model_dump(mode="json")
        return cls(
            id=static_documented_erratum_hardware_reference_id(payload),
            **payload,
        )

    @model_validator(mode="after")
    def validate_deterministic_id(
        self,
    ) -> "StaticDocumentedErratumHardwareReference":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_documented_erratum_hardware_reference_id(payload):
            raise ValueError("documented hardware reference ID mismatch")
        return self


StaticHardwareReference = (
    StaticOwnedSyntheticHardwareReference
    | StaticDocumentedErratumHardwareReference
)


def _detach_reference(value: StaticHardwareReference) -> StaticHardwareReference:
    payload = value.model_dump(mode="json")
    if value.reference_kind is StaticHardwareReferenceKind.OWNED_SYNTHETIC_CONDITION:
        return StaticOwnedSyntheticHardwareReference.model_validate(payload)
    if value.reference_kind is StaticHardwareReferenceKind.DOCUMENTED_HARDWARE_ERRATUM:
        return StaticDocumentedErratumHardwareReference.model_validate(payload)
    raise ValueError("unsupported static hardware reference kind")


class _StaticHardwareReferenceCatalogBody(DomainModel):
    contract: Literal["phase10d_static_hardware_reference_catalog_v1"]
    references: list[StaticHardwareReference] = Field(default_factory=list)

    @field_validator("references")
    @classmethod
    def normalize_references(
        cls, values: list[StaticHardwareReference]
    ) -> list[StaticHardwareReference]:
        detached = [_detach_reference(value) for value in values]
        reference_ids = [item.reference_id for item in detached]
        record_ids = [item.id for item in detached]
        if len(reference_ids) != len(set(reference_ids)):
            raise ValueError("hardware reference IDs must be unique")
        if len(record_ids) != len(set(record_ids)):
            raise ValueError("hardware reference record IDs must be unique")
        return sorted(detached, key=lambda item: (item.reference_id, item.id))


class StaticHardwareReferenceCatalog(_StaticHardwareReferenceCatalogBody):
    """Deterministic mixed-architecture source-backed reference catalog."""

    id: Identifier

    @classmethod
    def create(
        cls, *, references: list[StaticHardwareReference]
    ) -> "StaticHardwareReferenceCatalog":
        body = _StaticHardwareReferenceCatalogBody.model_validate(
            {
                "contract": PHASE10D_STATIC_HARDWARE_REFERENCE_CATALOG_CONTRACT,
                "references": references,
            }
        )
        payload = body.model_dump(mode="json")
        return cls(id=static_hardware_reference_catalog_id(payload), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "StaticHardwareReferenceCatalog":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_hardware_reference_catalog_id(payload):
            raise ValueError("static hardware reference catalog ID mismatch")
        return self
