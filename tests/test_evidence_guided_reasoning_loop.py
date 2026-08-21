"""Phase 9B2B Step 5 evidence-guided reasoning-loop tests."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.agents import ReasoningContext
from chipchain.models import Architecture
from chipchain.reasoning import (
    EvidenceFeedback,
    EvidenceFeedbackStatus,
    EvidenceGuidedReasoningLoop,
    MockReasoningProvider,
    ObservationFeedbackRelation,
    ReasoningAgentType,
    ReasoningEngine,
    ReasoningMemory,
    ReasoningObservation,
)


ROOT = Path(__file__).resolve().parents[1]


def _contracts():
    context = ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id="fixture-phase9b2b-step5-subject",
        affected_components=["fixture-arm-driver", "fixture-mmio-register"],
        available_evidence_ids=["fixture-existing-evidence-reference"],
        dynamic_trigger_fact_reference="dynamic-trigger-fact:fixture-reference",
    )
    hypothesis, requests, result = ReasoningEngine(
        provider=MockReasoningProvider()
    ).reason(context, role=ReasoningAgentType.CODE)
    return hypothesis, requests, result


def _observation(
    request,
    *,
    source_observation_id: str,
    relation: ObservationFeedbackRelation,
    observed_fact: str | None = None,
) -> ReasoningObservation:
    if observed_fact is None:
        observed_fact = (
            request.required_fact
            if relation is ObservationFeedbackRelation.MATCH
            else f"Contradiction of {request.required_fact}"
        )
    return ReasoningObservation.create(
        source_observation_id=source_observation_id,
        request=request,
        architecture=Architecture.ARM,
        observed_fact=observed_fact,
        relation=relation,
        metadata={"sample_type": "fixture"},
    )


def test_request_observation_feedback_and_memory_are_deterministic() -> None:
    hypothesis, requests, _ = _contracts()
    request = requests[0]
    first_observation = _observation(
        request,
        source_observation_id="fixture-observation-a",
        relation=ObservationFeedbackRelation.INCONCLUSIVE,
        observed_fact="Fixture observation is inconclusive",
    )
    second_observation = _observation(
        request,
        source_observation_id="fixture-observation-b",
        relation=ObservationFeedbackRelation.MATCH,
    )
    first = EvidenceFeedback.create(
        hypothesis,
        request,
        [first_observation, second_observation],
        metadata={"order": 1},
    )
    second = EvidenceFeedback.create(
        hypothesis,
        request,
        [second_observation, first_observation],
        metadata={"order": 2},
    )

    assert request.id == _contracts()[1][0].id
    assert first.id == second.id
    assert first.status is EvidenceFeedbackStatus.SUPPORTED
    assert EvidenceFeedback.model_validate_json(first.model_dump_json()) == first

    first_memory = ReasoningMemory.create(
        hypothesis,
        [first],
        metadata={"order": 1},
    )
    second_memory = ReasoningMemory.create(
        hypothesis,
        [second],
        metadata={"order": 2},
    )
    assert first_memory.id == second_memory.id
    assert ReasoningMemory.model_validate_json(
        first_memory.model_dump_json()
    ) == first_memory


def test_evidence_absence_produces_unknown_feedback() -> None:
    hypothesis, requests, initial = _contracts()
    updated, feedback, memory = EvidenceGuidedReasoningLoop().iterate(
        hypothesis,
        requests,
        [],
        initial,
    )

    assert all(item.status is EvidenceFeedbackStatus.UNKNOWN for item in feedback)
    assert updated.missing_evidence == initial.missing_evidence
    assert updated.supporting_evidence_ids == initial.supporting_evidence_ids
    assert updated.confidence == initial.confidence
    assert memory.request_ids == sorted(request.id for request in requests)


def test_matching_observation_supports_request_without_creating_evidence() -> None:
    hypothesis, requests, initial = _contracts()
    matched_request = requests[0]
    observation = _observation(
        matched_request,
        source_observation_id="fixture-matching-observation",
        relation=ObservationFeedbackRelation.MATCH,
    )
    updated, feedback, memory = EvidenceGuidedReasoningLoop().iterate(
        hypothesis,
        requests,
        [observation],
        initial,
    )
    feedback_by_request = {item.request_id: item for item in feedback}

    assert feedback_by_request[matched_request.id].status is (
        EvidenceFeedbackStatus.SUPPORTED
    )
    assert matched_request.id not in updated.missing_evidence
    assert observation.id not in updated.supporting_evidence_ids
    assert observation.source_observation_id not in updated.supporting_evidence_ids
    assert updated.supporting_evidence_ids == initial.supporting_evidence_ids
    assert memory.feedback_for(matched_request.id).id == (
        feedback_by_request[matched_request.id].id
    )


def test_contradicting_observation_produces_unsupported_feedback() -> None:
    hypothesis, requests, initial = _contracts()
    request = requests[0]
    observation = _observation(
        request,
        source_observation_id="fixture-contradicting-observation",
        relation=ObservationFeedbackRelation.CONTRADICT,
    )
    updated, feedback, _ = EvidenceGuidedReasoningLoop().iterate(
        hypothesis,
        requests,
        [observation],
        initial,
    )
    feedback_by_request = {item.request_id: item for item in feedback}

    assert feedback_by_request[request.id].status is (
        EvidenceFeedbackStatus.UNSUPPORTED
    )
    assert request.id not in updated.missing_evidence
    assert updated.confidence == initial.confidence


def test_matching_and_contradicting_observations_produce_conflict() -> None:
    hypothesis, requests, initial = _contracts()
    request = requests[0]
    observations = [
        _observation(
            request,
            source_observation_id="fixture-conflict-match",
            relation=ObservationFeedbackRelation.MATCH,
        ),
        _observation(
            request,
            source_observation_id="fixture-conflict-contradiction",
            relation=ObservationFeedbackRelation.CONTRADICT,
        ),
    ]
    updated, feedback, _ = EvidenceGuidedReasoningLoop().iterate(
        hypothesis,
        requests,
        observations,
        initial,
    )
    request_feedback = next(
        item for item in feedback if item.request_id == request.id
    )

    assert request_feedback.status is EvidenceFeedbackStatus.CONFLICT
    assert request.id in updated.missing_evidence
    assert len(request_feedback.matched_observation_ids) == 1
    assert len(request_feedback.contradicted_observation_ids) == 1


def test_feedback_fails_closed_for_invalid_observation_binding() -> None:
    hypothesis, requests, _ = _contracts()
    request = requests[0]
    wrong_fact = _observation(
        request,
        source_observation_id="fixture-invalid-match",
        relation=ObservationFeedbackRelation.MATCH,
        observed_fact="A different fixture fact",
    )
    wrong_architecture = ReasoningObservation.create(
        source_observation_id="fixture-wrong-architecture",
        request=request,
        architecture=Architecture.RISC_V,
        observed_fact=request.required_fact,
        relation=ObservationFeedbackRelation.MATCH,
    )

    with pytest.raises(ValueError, match="equal the requested fact"):
        EvidenceFeedback.create(hypothesis, request, [wrong_fact])
    with pytest.raises(ValueError, match="architecture mismatch"):
        EvidenceFeedback.create(hypothesis, request, [wrong_architecture])


def test_evidence_loop_has_no_verification_leakage() -> None:
    hypothesis, requests, initial = _contracts()
    updated, feedback, memory = EvidenceGuidedReasoningLoop().iterate(
        hypothesis,
        requests,
        [],
        initial,
    )
    forbidden_keys = {
        "attack_chain",
        "attack_chain_status",
        "evidence",
        "verification_record",
        "verification_score",
        "verification_status",
        "vulnerability_status",
        "vulnerability_verdict",
    }
    for item in (*feedback, memory, updated):
        assert forbidden_keys.isdisjoint(item.model_dump(mode="json"))
        assert not hasattr(item, "create_evidence")
        assert not hasattr(item, "create_verification_record")

    invalid = feedback[0].model_dump(mode="json")
    invalid["verification_status"] = "verified"
    with pytest.raises(ValidationError):
        EvidenceFeedback.model_validate(invalid)
    with pytest.raises(ValidationError, match="verdict fields"):
        EvidenceFeedback.create(
            hypothesis,
            requests[0],
            [],
            metadata={"vulnerability_verdict": "verified"},
        )
    with pytest.raises(ValidationError, match="domain truth objects"):
        EvidenceFeedback.create(
            hypothesis,
            requests[0],
            [],
            metadata={"nested": {"verification_record": "fixture-record"}},
        )

    for relative_path in (
        "src/chipchain/reasoning/evidence_loop.py",
        "src/chipchain/reasoning/feedback.py",
        "src/chipchain/reasoning/reasoning_memory.py",
    ):
        tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
        imported_modules = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        imported_names = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        assert not any(
            module.startswith(
                (
                    "chipchain.runtime",
                    "chipchain.verification",
                )
            )
            for module in imported_modules
        )
        assert {
            "AttackChain",
            "Evidence",
            "VerificationRecord",
        }.isdisjoint(imported_names)
