"""Evidence-guided, non-verifying reasoning loop for Phase 9B2B Step 5."""

from __future__ import annotations

from typing import TypeAlias

from chipchain.reasoning.evidence_request import EvidenceRequest
from chipchain.reasoning.feedback import (
    EvidenceFeedback,
    EvidenceFeedbackStatus,
    ReasoningObservation,
)
from chipchain.reasoning.hypothesis import AttackHypothesis
from chipchain.reasoning.reasoning_memory import ReasoningMemory
from chipchain.reasoning.reasoning_result import ReasoningResult


EvidenceLoopOutput: TypeAlias = tuple[
    ReasoningResult,
    list[EvidenceFeedback],
    ReasoningMemory,
]

_CONCLUSIVE_FEEDBACK = frozenset(
    {
        EvidenceFeedbackStatus.SUPPORTED,
        EvidenceFeedbackStatus.UNSUPPORTED,
    }
)


class EvidenceGuidedReasoningLoop:
    """Update reasoning from request-bound observation feedback only."""

    def iterate(
        self,
        hypothesis: AttackHypothesis,
        requests: list[EvidenceRequest],
        observations: list[ReasoningObservation],
        reasoning_result: ReasoningResult,
    ) -> EvidenceLoopOutput:
        """Return updated reasoning, feedback, and deterministic memory."""

        hypothesis_snapshot = AttackHypothesis.model_validate(
            hypothesis.model_dump(mode="json")
        )
        request_snapshots = [
            EvidenceRequest.model_validate(item.model_dump(mode="json"))
            for item in requests
        ]
        observation_snapshots = [
            ReasoningObservation.model_validate(item.model_dump(mode="json"))
            for item in observations
        ]
        result_snapshot = ReasoningResult.model_validate(
            reasoning_result.model_dump(mode="json")
        )
        result_snapshot.validate_against(hypothesis_snapshot)

        request_ids = [item.id for item in request_snapshots]
        if not request_snapshots:
            raise ValueError("evidence-guided loop requires at least one request")
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("evidence-guided loop request IDs must be unique")
        observation_ids = [item.id for item in observation_snapshots]
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("evidence-guided loop observation IDs must be unique")

        requests_by_id = {item.id: item for item in request_snapshots}
        observations_by_request: dict[str, list[ReasoningObservation]] = {
            request_id: [] for request_id in request_ids
        }
        for observation in observation_snapshots:
            request = requests_by_id.get(observation.request_id)
            if request is None:
                raise ValueError("observation references an unknown evidence request")
            if observation.architecture is not hypothesis_snapshot.architecture:
                raise ValueError("observation architecture mismatch")
            if observation.evidence_type is not request.evidence_type:
                raise ValueError("observation evidence category mismatch")
            observations_by_request[request.id].append(observation)

        feedback = [
            EvidenceFeedback.create(
                hypothesis_snapshot,
                request,
                sorted(
                    observations_by_request[request.id],
                    key=lambda item: item.id,
                ),
                metadata={
                    "domain_truth_creation": False,
                    "feedback_scope": "observation_matches_requested_fact_only",
                },
            )
            for request in sorted(request_snapshots, key=lambda item: item.id)
        ]
        memory = ReasoningMemory.create(
            hypothesis_snapshot,
            feedback,
            metadata={
                "domain_truth_creation": False,
                "memory_scope": "request_observation_feedback_only",
            },
        )
        updated_result = _updated_reasoning_result(
            hypothesis_snapshot,
            result_snapshot,
            feedback,
        )
        return updated_result, feedback, memory


def _updated_reasoning_result(
    hypothesis: AttackHypothesis,
    previous: ReasoningResult,
    feedback: list[EvidenceFeedback],
) -> ReasoningResult:
    conclusive_request_ids = {
        item.request_id
        for item in feedback
        if item.status in _CONCLUSIVE_FEEDBACK
    }
    unresolved_request_ids = {
        item.request_id
        for item in feedback
        if item.status not in _CONCLUSIVE_FEEDBACK
    }
    missing_references = (
        set(previous.missing_evidence).difference(conclusive_request_ids)
    ).union(unresolved_request_ids)
    feedback_steps = [
        (
            f"Observation feedback for request {item.request_id}: "
            f"{item.status.value}; observation match only, not verification"
        )
        for item in feedback
    ]
    reasoning_steps = list(previous.reasoning_steps)
    reasoning_steps.extend(
        step for step in feedback_steps if step not in reasoning_steps
    )
    metadata = dict(previous.metadata)
    metadata["reasoning_feedback_loop"] = {
        "contract": "phase9b2b_evidence_guided_reasoning_loop_v1",
        "domain_truth_creation": False,
        "feedback_ids": [item.id for item in feedback],
        "observation_semantics": "request_fact_comparison_only",
        "status_by_request": {
            item.request_id: item.status.value for item in feedback
        },
    }
    return ReasoningResult.create(
        hypothesis,
        reasoning_steps=reasoning_steps,
        supporting_evidence_ids=previous.supporting_evidence_ids,
        missing_evidence=sorted(missing_references),
        confidence=previous.confidence,
        metadata=metadata,
    )
