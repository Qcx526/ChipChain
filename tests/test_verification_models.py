"""Model, condition, feature, catalog, and score contract tests."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from chipchain.knowledge import KnowledgeNode, KnowledgeNodeKind
from chipchain.models import Architecture, Evidence, EvidenceType, Layer
from chipchain.verification import (
    CandidateVerificationStatus,
    ConditionKind,
    ConditionStatus,
    ConditionVerifier,
    EvidenceCatalog,
    HardwareAddress,
    ProgramAddress,
    VerificationRecord,
    VerificationScoreConfig,
    VerificationStatus,
    VerificationSubjectKind,
)


def _condition(kind: KnowledgeNodeKind, evidence_ids: list[str]) -> KnowledgeNode:
    return KnowledgeNode(
        id=f"{kind.value}:fixture",
        kind=kind,
        label="fixture condition",
        architecture=Architecture.ARM,
        layer=Layer.DRIVER,
        evidence_ids=evidence_ids,
        metadata={"input": "request", "event": "ioctl", "entrypoint": "handler"},
    )


def _condition_evidence(node_id: str, assertion: str) -> Evidence:
    return Evidence(
        id=f"condition-evidence:{assertion}",
        type=EvidenceType.DYNAMIC_ANALYSIS,
        source="authorized-fixture-observer",
        confidence=1.0,
        verified=True,
        metadata={"condition_node_id": node_id, "condition_assertion": assertion, "fixture": True},
    )


def test_verification_enums_are_independent_and_closed():
    assert VerificationStatus.UNKNOWN.value == "unknown"
    assert ConditionStatus.UNKNOWN.value == "unknown"
    assert CandidateVerificationStatus.PARTIALLY_VERIFIED.value == "partially_verified"
    assert ConditionKind.TRIGGER.value == "trigger"


def test_verification_record_round_trip_and_deterministic_id():
    record = VerificationRecord.create(
        architecture=Architecture.ARM,
        subject_kind=VerificationSubjectKind.BEHAVIOR_EDGE,
        subject_id="edge-a",
        status=VerificationStatus.UNKNOWN,
        verifier="fixture-verifier",
        evidence_ids=["ev-a"],
        rule_ids=["rule-a"],
        messages=["missing support"],
    )
    restored = VerificationRecord.model_validate_json(record.model_dump_json())
    assert restored == record
    assert VerificationRecord.create(
        architecture=Architecture.ARM,
        subject_kind=VerificationSubjectKind.BEHAVIOR_EDGE,
        subject_id="edge-a",
        status=VerificationStatus.VERIFIED,
        verifier="fixture-verifier",
    ).id == record.id


@pytest.mark.parametrize("assertion,expected", [("satisfied", ConditionStatus.SATISFIED), ("unsatisfied", ConditionStatus.UNSATISFIED)])
def test_condition_requires_explicit_structured_evidence(assertion: str, expected: ConditionStatus):
    node = _condition(KnowledgeNodeKind.TRIGGER, [f"condition-evidence:{assertion}"])
    evidence = _condition_evidence(node.id, assertion)
    assessment = ConditionVerifier().verify(node, EvidenceCatalog([evidence]))
    assert assessment.status is expected


def test_condition_missing_information_is_unknown_and_llm_does_not_satisfy():
    node = _condition(KnowledgeNodeKind.PRECONDITION, ["llm-evidence"])
    evidence = Evidence(
        id="llm-evidence",
        type=EvidenceType.LLM_SEMANTIC,
        source="fixture-llm",
        confidence=1.0,
        verified=True,
        metadata={"condition_node_id": node.id, "condition_assertion": "satisfied"},
    )
    assessment = ConditionVerifier().verify(node, EvidenceCatalog([evidence]))
    assert assessment.status is ConditionStatus.UNKNOWN


def test_evidence_inventory_recomputes_missing_unverified_and_non_llm_counts():
    verified = Evidence(id="verified", type=EvidenceType.STATIC_ANALYSIS, source="fixture", confidence=1.0, verified=True)
    llm = Evidence(id="llm", type=EvidenceType.LLM_SEMANTIC, source="fixture", confidence=1.0, verified=True)
    inventory = EvidenceCatalog([verified, llm]).inventory(["verified", "llm", "missing"])
    assert inventory.required_evidence_count == 3
    assert inventory.resolved_evidence_count == 2
    assert inventory.verified_non_llm_evidence_ids == ["verified"]
    assert inventory.unknown_evidence_ids == ["llm", "missing"]


def test_evidence_inventory_records_explicitly_rejected_support_separately():
    evidence = Evidence(
        id="conflicting",
        type=EvidenceType.STATIC_ANALYSIS,
        source="fixture",
        confidence=1.0,
        verified=True,
    )
    inventory = EvidenceCatalog([evidence]).inventory(
        ["conflicting"], rejected_evidence_ids=["conflicting"]
    )
    assert inventory.rejected_evidence_count == 1
    assert inventory.rejected_evidence_ids == ["conflicting"]
    assert inventory.verified_non_llm_evidence_count == 0


def test_address_namespaces_canonicalize_but_remain_distinct_models():
    assert ProgramAddress(value="0X00010008").value == "0x10008"
    assert HardwareAddress(value="0X40000000").value == "0x40000000"
    assert type(ProgramAddress(value="0x10008")) is not type(HardwareAddress(value="0x10008"))


def test_score_config_requires_exact_unit_sum_and_profile():
    valid = {
        "behavior_evidence": 0.2,
        "entity_link": 0.2,
        "knowledge_evidence": 0.2,
        "conditions": 0.2,
        "architecture_rules": 0.2,
        "metadata": {"profile": "engineering_mvp_uncalibrated"},
    }
    assert VerificationScoreConfig.model_validate(json.loads(json.dumps(valid)))
    invalid = dict(valid)
    invalid["conditions"] = 0.1
    with pytest.raises(ValidationError, match="sum exactly"):
        VerificationScoreConfig.model_validate(invalid)
