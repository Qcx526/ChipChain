"""Offline end-to-end coverage for the Phase 9B2A evidence-chain demo."""

from __future__ import annotations

from scripts.demo_phase9b2a_dynamic_verification import main

from chipchain.verification.aggregation import StaticDynamicAggregationStatus
from chipchain.verification.enums import (
    VerificationStatus,
    VerificationSubjectKind,
)


def test_phase9b2a_demo_is_offline_and_observation_scoped(capsys) -> None:
    dynamic_record, aggregation = main()
    output = capsys.readouterr().out

    assert dynamic_record.subject_kind is (
        VerificationSubjectKind.DYNAMIC_TRIGGER_OBSERVATION
    )
    assert dynamic_record.status is VerificationStatus.VERIFIED
    assert aggregation.status is StaticDynamicAggregationStatus.CORROBORATED
    assert dynamic_record.evidence_ids == dynamic_record.supporting_evidence_ids
    assert aggregation.dynamic_evidence_ids == dynamic_record.evidence_ids
    assert aggregation.static_evidence_ids == [
        "fixture-phase9b2a-static-trigger-evidence"
    ]

    assert "Dynamic trigger verification:\nVERIFIED\n" in output
    assert "Aggregation:\ncorroborated\n" in output
    assert "observation matches trigger fact only" in output

    serialized_record = dynamic_record.model_dump(mode="json")
    serialized_aggregation = aggregation.model_dump(mode="json")
    forbidden_fields = {
        "attack_chain",
        "behavior_edge",
        "causality_verdict",
        "interaction_status",
        "verification_score",
        "vulnerability_verdict",
    }
    assert forbidden_fields.isdisjoint(serialized_record)
    assert forbidden_fields.isdisjoint(serialized_aggregation)
