"""Deterministic code-focused reasoning contract agent."""

from chipchain.agents.base import DeterministicMockReasoningAgent
from chipchain.reasoning.enums import (
    EvidenceCategory,
    EvidencePriority,
    ReasoningAgentType,
)


class CodeAgent(DeterministicMockReasoningAgent):
    """Reason about referenced software behavior without verifying it."""

    role = ReasoningAgentType.CODE
    hypothesis_template = (
        "Code behavior for {subject_id} may participate in a cross-layer condition"
    )
    evidence_types = (
        EvidenceCategory.STATIC_BEHAVIOR,
        EvidenceCategory.RUNTIME_OBSERVATION,
    )
    evidence_request_specs = (
        (
            EvidenceCategory.STATIC_BEHAVIOR,
            "Resolve the static behavior referenced by {subject_id}",
            EvidencePriority.HIGH,
            False,
        ),
        (
            EvidenceCategory.RUNTIME_OBSERVATION,
            "Observe the referenced code behavior for {subject_id} at runtime",
            EvidencePriority.MEDIUM,
            True,
        ),
    )
    reasoning_step_template = (
        "CodeAgent considered static and runtime references for {subject_id}"
    )
