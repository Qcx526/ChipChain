"""Tests for strict Phase 8 shared-context and output contracts."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from chipchain.multi_agent import (
    AgentExecutionRecord,
    EvidenceAnalysis,
    MultiAgentContext,
    SecurityReasoningAssessment,
)


def test_multi_agent_context_round_trip_and_identity(multi_agent_context) -> None:
    """All agents receive one serializable context with one retrieval result."""

    restored = MultiAgentContext.model_validate_json(
        multi_agent_context.model_dump_json()
    )

    assert restored == multi_agent_context
    assert restored.candidate_context.candidate_id == restored.candidate_id
    assert [chunk.architecture.value if chunk.architecture else None for chunk in restored.retrieved_chunks] == [
        "arm",
        None,
        "arm",
    ]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("candidate_id", "wrong-candidate", "candidate ID"),
        ("architecture", "risc_v", "architecture"),
    ],
)
def test_multi_agent_context_rejects_identity_mismatch(
    field: str,
    value: str,
    message: str,
    multi_agent_context,
) -> None:
    data = multi_agent_context.model_dump(mode="json")
    data[field] = value

    with pytest.raises(ValidationError, match=message):
        MultiAgentContext.model_validate(data)


def test_agent_status_models_cannot_express_verification_or_scores(
    multi_agent_context,
) -> None:
    base = {
        "candidate_id": multi_agent_context.candidate_id,
        "architecture": "arm",
        "missing_behavior_evidence": False,
        "missing_knowledge_evidence": False,
        "analysis_status": "context_ready",
    }

    with pytest.raises(ValidationError):
        EvidenceAnalysis.model_validate({**base, "analysis_status": "verified"})
    with pytest.raises(ValidationError):
        EvidenceAnalysis.model_validate({**base, "confidence": 0.93})
    with pytest.raises(ValidationError):
        SecurityReasoningAssessment.model_validate(
            {
                "candidate_id": multi_agent_context.candidate_id,
                "architecture": "arm",
                "summary": "fixture",
                "semantic_status": "confirmed",
            }
        )


def test_execution_record_requires_sha256_and_consistent_outcome(
    multi_agent_context,
) -> None:
    values = {
        "sequence": 1,
        "role": "evidence_analyst",
        "candidate_id": multi_agent_context.candidate_id,
        "architecture": "arm",
        "input_digest": "0" * 64,
        "prompt_digest": "1" * 64,
        "output_digest": "2" * 64,
        "execution_status": "completed",
    }
    assert AgentExecutionRecord.model_validate(values).error_type is None

    with pytest.raises(ValidationError, match="SHA-256"):
        AgentExecutionRecord.model_validate({**values, "input_digest": "short"})
    with pytest.raises(ValidationError, match="completed execution"):
        AgentExecutionRecord.model_validate({**values, "output_digest": None})
