"""Phase 9B2A static/dynamic trigger-fact aggregation tests."""

from __future__ import annotations

import itertools

import pytest
from pydantic import ValidationError

from chipchain.models import Architecture
from chipchain.verification.aggregation import (
    StaticDynamicAggregationStatus,
    StaticDynamicFactAggregation,
)
from chipchain.verification.enums import (
    VerificationStatus,
    VerificationSubjectKind,
)
from chipchain.verification.errors import VerificationInputError
from chipchain.verification.models import VerificationRecord


INTERACTION_ID = "synthetic-phase9b2a-interaction"
TRIGGER_ID = "synthetic-trigger-behavior"


def _static_record(
    status: VerificationStatus,
    *,
    interaction_id: str = INTERACTION_ID,
    architecture: Architecture = Architecture.ARM,
    subject_id: str = f"trigger_behavior:{TRIGGER_ID}",
    evidence_ids: list[str] | None = None,
    supporting_evidence_ids: list[str] | None = None,
) -> VerificationRecord:
    return VerificationRecord.create(
        interaction_id=interaction_id,
        architecture=architecture,
        subject_kind=VerificationSubjectKind.INTERACTION_PARTICIPANT,
        subject_id=subject_id,
        status=status,
        verifier="phase9ar_explicit_binding_v1",
        evidence_ids=evidence_ids or [],
        supporting_evidence_ids=supporting_evidence_ids or [],
        rule_ids=["binding:explicit-role-source:v1"],
    )


def _dynamic_record(
    status: VerificationStatus,
    *,
    suffix: str = "one",
    interaction_id: str = INTERACTION_ID,
    architecture: Architecture = Architecture.ARM,
    trigger_id: str = TRIGGER_ID,
    reference_role: str = "trigger_behavior",
    evidence_ids: list[str] | None = None,
    supporting_evidence_ids: list[str] | None = None,
) -> VerificationRecord:
    return VerificationRecord.create(
        interaction_id=interaction_id,
        architecture=architecture,
        subject_kind=VerificationSubjectKind.DYNAMIC_TRIGGER_OBSERVATION,
        subject_id=f"dynamic-binding-{suffix}",
        status=status,
        verifier="phase9b2a_dynamic_trigger_observation_v1",
        evidence_ids=evidence_ids or [],
        supporting_evidence_ids=supporting_evidence_ids or [],
        rule_ids=["dynamic:trigger-observation:exact-v1"],
        metadata={
            "interaction_reference_id": trigger_id,
            "reference_role": reference_role,
        },
    )


@pytest.mark.parametrize(
    "static_status,dynamic_status,expected",
    [
        (
            VerificationStatus.VERIFIED,
            VerificationStatus.VERIFIED,
            StaticDynamicAggregationStatus.CORROBORATED,
        ),
        (
            VerificationStatus.VERIFIED,
            VerificationStatus.UNKNOWN,
            StaticDynamicAggregationStatus.STATIC_ONLY,
        ),
        (
            VerificationStatus.VERIFIED,
            VerificationStatus.REJECTED,
            StaticDynamicAggregationStatus.CONFLICT,
        ),
        (
            VerificationStatus.UNKNOWN,
            VerificationStatus.VERIFIED,
            StaticDynamicAggregationStatus.DYNAMIC_ONLY,
        ),
        (
            VerificationStatus.UNKNOWN,
            VerificationStatus.UNKNOWN,
            StaticDynamicAggregationStatus.INSUFFICIENT,
        ),
        (
            VerificationStatus.UNKNOWN,
            VerificationStatus.REJECTED,
            StaticDynamicAggregationStatus.DYNAMIC_REJECTED,
        ),
        (
            VerificationStatus.REJECTED,
            VerificationStatus.VERIFIED,
            StaticDynamicAggregationStatus.CONFLICT,
        ),
        (
            VerificationStatus.REJECTED,
            VerificationStatus.UNKNOWN,
            StaticDynamicAggregationStatus.STATIC_REJECTED,
        ),
        (
            VerificationStatus.REJECTED,
            VerificationStatus.REJECTED,
            StaticDynamicAggregationStatus.BOTH_REJECTED,
        ),
    ],
)
def test_three_by_three_status_matrix(
    static_status: VerificationStatus,
    dynamic_status: VerificationStatus,
    expected: StaticDynamicAggregationStatus,
) -> None:
    result = StaticDynamicFactAggregation.create(
        _static_record(static_status),
        _dynamic_record(dynamic_status),
    )

    assert result.status is expected


def test_input_order_does_not_change_result() -> None:
    static = _static_record(VerificationStatus.VERIFIED)
    dynamic_one = _dynamic_record(VerificationStatus.VERIFIED, suffix="one")
    dynamic_two = _dynamic_record(VerificationStatus.UNKNOWN, suffix="two")
    expected = StaticDynamicFactAggregation.from_records(
        [static, dynamic_one, dynamic_two]
    )

    for records in itertools.permutations([static, dynamic_one, dynamic_two]):
        actual = StaticDynamicFactAggregation.from_records(records)
        assert actual == expected
        assert actual.model_dump(mode="json") == expected.model_dump(mode="json")


@pytest.mark.parametrize(
    "static_status,dynamic_status",
    [
        (VerificationStatus.VERIFIED, VerificationStatus.REJECTED),
        (VerificationStatus.REJECTED, VerificationStatus.VERIFIED),
    ],
)
def test_verified_rejected_pairs_are_conflicts(
    static_status: VerificationStatus,
    dynamic_status: VerificationStatus,
) -> None:
    result = StaticDynamicFactAggregation.create(
        _static_record(static_status),
        _dynamic_record(dynamic_status),
    )

    assert result.status is StaticDynamicAggregationStatus.CONFLICT


def test_multiple_dynamic_verified_rejected_records_fail_as_conflict() -> None:
    result = StaticDynamicFactAggregation.create(
        _static_record(VerificationStatus.UNKNOWN),
        [
            _dynamic_record(VerificationStatus.VERIFIED, suffix="verified"),
            _dynamic_record(VerificationStatus.REJECTED, suffix="rejected"),
            _dynamic_record(VerificationStatus.UNKNOWN, suffix="unknown"),
        ],
    )

    assert result.status is StaticDynamicAggregationStatus.CONFLICT


def test_preserves_static_and_dynamic_evidence_ids_separately() -> None:
    result = StaticDynamicFactAggregation.create(
        _static_record(
            VerificationStatus.VERIFIED,
            evidence_ids=["shared-evidence", "static-evidence"],
            supporting_evidence_ids=["static-evidence"],
        ),
        [
            _dynamic_record(
                VerificationStatus.VERIFIED,
                suffix="one",
                evidence_ids=["dynamic-one", "shared-evidence"],
                supporting_evidence_ids=["dynamic-one"],
            ),
            _dynamic_record(
                VerificationStatus.VERIFIED,
                suffix="two",
                evidence_ids=["dynamic-two"],
                supporting_evidence_ids=["dynamic-two"],
            ),
        ],
    )

    assert result.static_evidence_ids == ["shared-evidence", "static-evidence"]
    assert result.static_supporting_evidence_ids == ["static-evidence"]
    assert result.dynamic_evidence_ids == [
        "dynamic-one",
        "dynamic-two",
        "shared-evidence",
    ]
    assert result.dynamic_supporting_evidence_ids == [
        "dynamic-one",
        "dynamic-two",
    ]


def test_result_has_no_security_or_interaction_verdict_fields() -> None:
    result = StaticDynamicFactAggregation.create(
        _static_record(VerificationStatus.VERIFIED),
        _dynamic_record(VerificationStatus.VERIFIED),
    )
    serialized = result.model_dump(mode="json")

    forbidden_fields = {
        "vulnerability_verdict",
        "causality_verdict",
        "causal_verdict",
        "attack_chain",
        "attack_chain_verdict",
        "interaction_status",
        "verification_score",
        "score",
    }
    assert forbidden_fields.isdisjoint(serialized)
    assert result.status is StaticDynamicAggregationStatus.CORROBORATED


def test_round_trip_preserves_deterministic_identity() -> None:
    result = StaticDynamicFactAggregation.create(
        _static_record(VerificationStatus.UNKNOWN),
        _dynamic_record(VerificationStatus.VERIFIED),
    )

    restored = StaticDynamicFactAggregation.model_validate(
        result.model_dump(mode="json")
    )
    assert restored == result


@pytest.mark.parametrize(
    "dynamic",
    [
        _dynamic_record(
            VerificationStatus.UNKNOWN,
            interaction_id="different-interaction",
        ),
        _dynamic_record(
            VerificationStatus.UNKNOWN,
            architecture=Architecture.RISC_V,
        ),
        _dynamic_record(
            VerificationStatus.UNKNOWN,
            trigger_id="different-trigger",
        ),
        _dynamic_record(
            VerificationStatus.UNKNOWN,
            reference_role="propagation_behavior",
        ),
    ],
)
def test_identity_and_trigger_join_mismatches_fail_closed(
    dynamic: VerificationRecord,
) -> None:
    with pytest.raises(VerificationInputError):
        StaticDynamicFactAggregation.create(
            _static_record(VerificationStatus.UNKNOWN), dynamic
        )


def test_duplicate_dynamic_record_fails_closed() -> None:
    dynamic = _dynamic_record(VerificationStatus.UNKNOWN)

    with pytest.raises(VerificationInputError, match="duplicate"):
        StaticDynamicFactAggregation.create(
            _static_record(VerificationStatus.UNKNOWN), [dynamic, dynamic]
        )


def test_non_trigger_static_record_fails_closed() -> None:
    static = _static_record(
        VerificationStatus.UNKNOWN,
        subject_id=f"target_vulnerability:{TRIGGER_ID}",
    )

    with pytest.raises(VerificationInputError, match="trigger_behavior"):
        StaticDynamicFactAggregation.create(
            static, _dynamic_record(VerificationStatus.UNKNOWN)
        )


def test_tampered_aggregation_status_is_rejected() -> None:
    result = StaticDynamicFactAggregation.create(
        _static_record(VerificationStatus.VERIFIED),
        _dynamic_record(VerificationStatus.VERIFIED),
    )
    data = result.model_dump(mode="json")
    data["status"] = StaticDynamicAggregationStatus.STATIC_ONLY.value

    with pytest.raises(ValidationError, match="aggregation status"):
        StaticDynamicFactAggregation.model_validate(data)
