"""Read-only Phase 9B2A aggregation of static and dynamic trigger facts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from enum import Enum
from typing import Self

from pydantic import Field, ValidationError, field_validator, model_validator

from chipchain.models import Architecture
from chipchain.models.common import DomainModel, Identifier
from chipchain.verification.enums import (
    InteractionReferenceRole,
    VerificationStatus,
    VerificationSubjectKind,
)
from chipchain.verification.errors import VerificationInputError
from chipchain.verification.models import VerificationRecord


class StaticDynamicAggregationStatus(str, Enum):
    """Closed outcomes for static/dynamic trigger-fact aggregation."""

    CORROBORATED = "corroborated"
    STATIC_ONLY = "static_only"
    DYNAMIC_ONLY = "dynamic_only"
    INSUFFICIENT = "insufficient"
    CONFLICT = "conflict"
    STATIC_REJECTED = "static_rejected"
    DYNAMIC_REJECTED = "dynamic_rejected"
    BOTH_REJECTED = "both_rejected"


_STATUS_MATRIX = {
    (VerificationStatus.VERIFIED, VerificationStatus.VERIFIED): (
        StaticDynamicAggregationStatus.CORROBORATED
    ),
    (VerificationStatus.VERIFIED, VerificationStatus.UNKNOWN): (
        StaticDynamicAggregationStatus.STATIC_ONLY
    ),
    (VerificationStatus.VERIFIED, VerificationStatus.REJECTED): (
        StaticDynamicAggregationStatus.CONFLICT
    ),
    (VerificationStatus.UNKNOWN, VerificationStatus.VERIFIED): (
        StaticDynamicAggregationStatus.DYNAMIC_ONLY
    ),
    (VerificationStatus.UNKNOWN, VerificationStatus.UNKNOWN): (
        StaticDynamicAggregationStatus.INSUFFICIENT
    ),
    (VerificationStatus.UNKNOWN, VerificationStatus.REJECTED): (
        StaticDynamicAggregationStatus.DYNAMIC_REJECTED
    ),
    (VerificationStatus.REJECTED, VerificationStatus.VERIFIED): (
        StaticDynamicAggregationStatus.CONFLICT
    ),
    (VerificationStatus.REJECTED, VerificationStatus.UNKNOWN): (
        StaticDynamicAggregationStatus.STATIC_REJECTED
    ),
    (VerificationStatus.REJECTED, VerificationStatus.REJECTED): (
        StaticDynamicAggregationStatus.BOTH_REJECTED
    ),
}


def static_dynamic_aggregation_id(
    interaction_id: str,
    architecture: Architecture,
    interaction_reference_id: str,
    static_record_id: str,
    static_status: VerificationStatus,
    dynamic_record_statuses: dict[str, VerificationStatus],
    status: StaticDynamicAggregationStatus,
    static_evidence_ids: list[str],
    static_supporting_evidence_ids: list[str],
    dynamic_evidence_ids: list[str],
    dynamic_supporting_evidence_ids: list[str],
) -> str:
    """Return the deterministic identity of one aggregation snapshot."""

    material = {
        "interaction_id": interaction_id,
        "architecture": architecture.value,
        "reference_role": InteractionReferenceRole.TRIGGER_BEHAVIOR.value,
        "interaction_reference_id": interaction_reference_id,
        "static_record_id": static_record_id,
        "static_status": static_status.value,
        "dynamic_record_statuses": [
            [record_id, record_status.value]
            for record_id, record_status in sorted(dynamic_record_statuses.items())
        ],
        "status": status.value,
        "static_evidence_ids": sorted(static_evidence_ids),
        "static_supporting_evidence_ids": sorted(
            static_supporting_evidence_ids
        ),
        "dynamic_evidence_ids": sorted(dynamic_evidence_ids),
        "dynamic_supporting_evidence_ids": sorted(
            dynamic_supporting_evidence_ids
        ),
    }
    digest = hashlib.sha256(
        json.dumps(material, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()[:24]
    return f"static-dynamic-aggregation:{digest}"


class StaticDynamicFactAggregation(DomainModel):
    """A detached static/dynamic trigger-fact status aggregation.

    This is an observation-level correlation result. It does not alter or
    verify an interaction, vulnerability, causal relation, or attack chain.
    """

    id: Identifier
    interaction_id: Identifier
    architecture: Architecture
    interaction_reference_id: Identifier
    reference_role: InteractionReferenceRole = (
        InteractionReferenceRole.TRIGGER_BEHAVIOR
    )
    status: StaticDynamicAggregationStatus
    static_record_id: Identifier
    static_status: VerificationStatus
    dynamic_record_ids: list[Identifier]
    dynamic_record_statuses: dict[Identifier, VerificationStatus]
    static_evidence_ids: list[Identifier] = Field(default_factory=list)
    static_supporting_evidence_ids: list[Identifier] = Field(default_factory=list)
    dynamic_evidence_ids: list[Identifier] = Field(default_factory=list)
    dynamic_supporting_evidence_ids: list[Identifier] = Field(default_factory=list)

    @field_validator(
        "dynamic_record_ids",
        "static_evidence_ids",
        "static_supporting_evidence_ids",
        "dynamic_evidence_ids",
        "dynamic_supporting_evidence_ids",
    )
    @classmethod
    def normalize_identifier_lists(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("aggregation identifier lists must not contain duplicates")
        return sorted(values)

    @field_validator("dynamic_record_statuses")
    @classmethod
    def normalize_dynamic_statuses(
        cls, values: dict[str, VerificationStatus]
    ) -> dict[str, VerificationStatus]:
        return dict(sorted(values.items()))

    @model_validator(mode="after")
    def validate_aggregation(self) -> Self:
        if self.reference_role is not InteractionReferenceRole.TRIGGER_BEHAVIOR:
            raise ValueError("aggregation reference_role must be trigger_behavior")
        if not self.dynamic_record_ids:
            raise ValueError("aggregation requires at least one Dynamic VerificationRecord")
        if set(self.dynamic_record_ids) != set(self.dynamic_record_statuses):
            raise ValueError(
                "dynamic_record_ids must match dynamic_record_statuses keys"
            )
        if not set(self.static_supporting_evidence_ids).issubset(
            self.static_evidence_ids
        ):
            raise ValueError(
                "static supporting Evidence IDs must be a subset of static Evidence IDs"
            )
        if not set(self.dynamic_supporting_evidence_ids).issubset(
            self.dynamic_evidence_ids
        ):
            raise ValueError(
                "dynamic supporting Evidence IDs must be a subset of dynamic Evidence IDs"
            )

        expected_status = _aggregation_status(
            self.static_status,
            list(self.dynamic_record_statuses.values()),
        )
        if self.status is not expected_status:
            raise ValueError("aggregation status does not match input record statuses")
        expected_id = static_dynamic_aggregation_id(
            self.interaction_id,
            self.architecture,
            self.interaction_reference_id,
            self.static_record_id,
            self.static_status,
            self.dynamic_record_statuses,
            self.status,
            self.static_evidence_ids,
            self.static_supporting_evidence_ids,
            self.dynamic_evidence_ids,
            self.dynamic_supporting_evidence_ids,
        )
        if self.id != expected_id:
            raise ValueError("StaticDynamicFactAggregation ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        static_record: VerificationRecord,
        dynamic_records: VerificationRecord | Sequence[VerificationRecord],
    ) -> Self:
        """Aggregate one static record and one or more dynamic records."""

        records = (
            [dynamic_records]
            if isinstance(dynamic_records, VerificationRecord)
            else list(dynamic_records)
        )
        return cls.from_records([static_record, *records])

    @classmethod
    def from_records(cls, records: Iterable[VerificationRecord]) -> Self:
        """Classify records by subject kind, independent of input order."""

        snapshots = [_snapshot_record(record) for record in records]
        record_ids = [record.id for record in snapshots]
        if len(record_ids) != len(set(record_ids)):
            raise VerificationInputError(
                "aggregation input contains duplicate VerificationRecord IDs"
            )

        dynamic_records = [
            record
            for record in snapshots
            if record.subject_kind
            is VerificationSubjectKind.DYNAMIC_TRIGGER_OBSERVATION
        ]
        static_records = [
            record
            for record in snapshots
            if record.subject_kind
            is not VerificationSubjectKind.DYNAMIC_TRIGGER_OBSERVATION
        ]
        if len(static_records) != 1:
            raise VerificationInputError(
                "aggregation requires exactly one Static VerificationRecord"
            )
        if not dynamic_records:
            raise VerificationInputError(
                "aggregation requires at least one Dynamic VerificationRecord"
            )

        static_record = static_records[0]
        interaction_reference_id = _static_trigger_reference(static_record)
        for record in dynamic_records:
            _validate_dynamic_record(
                record,
                interaction_id=static_record.interaction_id,
                architecture=static_record.architecture,
                interaction_reference_id=interaction_reference_id,
            )

        dynamic_record_statuses = {
            record.id: record.status for record in dynamic_records
        }
        status = _aggregation_status(
            static_record.status,
            list(dynamic_record_statuses.values()),
        )
        dynamic_record_ids = sorted(dynamic_record_statuses)
        static_evidence_ids = list(static_record.evidence_ids)
        static_supporting_evidence_ids = list(
            static_record.supporting_evidence_ids
        )
        dynamic_evidence_ids = sorted(
            {item for record in dynamic_records for item in record.evidence_ids}
        )
        dynamic_supporting_evidence_ids = sorted(
            {
                item
                for record in dynamic_records
                for item in record.supporting_evidence_ids
            }
        )
        aggregation_id = static_dynamic_aggregation_id(
            static_record.interaction_id,
            static_record.architecture,
            interaction_reference_id,
            static_record.id,
            static_record.status,
            dynamic_record_statuses,
            status,
            static_evidence_ids,
            static_supporting_evidence_ids,
            dynamic_evidence_ids,
            dynamic_supporting_evidence_ids,
        )
        return cls(
            id=aggregation_id,
            interaction_id=static_record.interaction_id,
            architecture=static_record.architecture,
            interaction_reference_id=interaction_reference_id,
            status=status,
            static_record_id=static_record.id,
            static_status=static_record.status,
            dynamic_record_ids=dynamic_record_ids,
            dynamic_record_statuses=dynamic_record_statuses,
            static_evidence_ids=static_evidence_ids,
            static_supporting_evidence_ids=static_supporting_evidence_ids,
            dynamic_evidence_ids=dynamic_evidence_ids,
            dynamic_supporting_evidence_ids=dynamic_supporting_evidence_ids,
        )


def _snapshot_record(record: VerificationRecord) -> VerificationRecord:
    if not isinstance(record, VerificationRecord):
        raise VerificationInputError(
            "aggregation inputs must be VerificationRecord instances"
        )
    try:
        return VerificationRecord.model_validate(record.model_dump(mode="json"))
    except ValidationError as exc:
        raise VerificationInputError(
            "aggregation VerificationRecord revalidation failed"
        ) from exc


def _static_trigger_reference(record: VerificationRecord) -> str:
    if record.subject_kind is not VerificationSubjectKind.INTERACTION_PARTICIPANT:
        raise VerificationInputError(
            "Static VerificationRecord must describe an interaction participant"
        )
    role, separator, reference_id = record.subject_id.partition(":")
    if (
        separator != ":"
        or role != InteractionReferenceRole.TRIGGER_BEHAVIOR.value
        or not reference_id
    ):
        raise VerificationInputError(
            "Static VerificationRecord must identify trigger_behavior:<reference-id>"
        )
    return reference_id


def _validate_dynamic_record(
    record: VerificationRecord,
    *,
    interaction_id: str,
    architecture: Architecture,
    interaction_reference_id: str,
) -> None:
    if record.interaction_id != interaction_id:
        raise VerificationInputError(
            "Static and Dynamic VerificationRecord interaction IDs differ"
        )
    if record.architecture is not architecture:
        raise VerificationInputError(
            "Static and Dynamic VerificationRecord architectures differ"
        )
    if (
        record.metadata.get("reference_role")
        != InteractionReferenceRole.TRIGGER_BEHAVIOR.value
    ):
        raise VerificationInputError(
            "Dynamic VerificationRecord reference_role must be trigger_behavior"
        )
    if record.metadata.get("interaction_reference_id") != interaction_reference_id:
        raise VerificationInputError(
            "Static and Dynamic VerificationRecord trigger references differ"
        )


def _aggregation_status(
    static_status: VerificationStatus,
    dynamic_statuses: list[VerificationStatus],
) -> StaticDynamicAggregationStatus:
    statuses = set(dynamic_statuses)
    if not statuses:
        raise ValueError("at least one Dynamic VerificationRecord status is required")
    if {
        VerificationStatus.VERIFIED,
        VerificationStatus.REJECTED,
    }.issubset(statuses):
        return StaticDynamicAggregationStatus.CONFLICT
    if VerificationStatus.REJECTED in statuses:
        dynamic_status = VerificationStatus.REJECTED
    elif VerificationStatus.VERIFIED in statuses:
        dynamic_status = VerificationStatus.VERIFIED
    else:
        dynamic_status = VerificationStatus.UNKNOWN
    return _STATUS_MATRIX[(static_status, dynamic_status)]
