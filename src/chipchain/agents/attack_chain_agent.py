"""Deterministic cross-layer sequence reasoning contract agent."""

from chipchain.agents.base import DeterministicMockReasoningAgent
from chipchain.reasoning.enums import (
    EvidenceCategory,
    EvidencePriority,
    ReasoningAgentType,
)


class AttackChainAgent(DeterministicMockReasoningAgent):
    """Reason about a possible sequence without creating an AttackChain."""

    role = ReasoningAgentType.ATTACK_CHAIN
    hypothesis_template = (
        "A cross-layer sequence involving {subject_id} remains a hypothesis"
    )
    evidence_types = (
        EvidenceCategory.STATIC_BEHAVIOR,
        EvidenceCategory.RUNTIME_OBSERVATION,
        EvidenceCategory.MMIO_ACCESS,
        EvidenceCategory.PRIVILEGE_TRANSITION,
    )
    evidence_request_specs = (
        (
            EvidenceCategory.STATIC_BEHAVIOR,
            "Resolve the proposed sequence's static step for {subject_id}",
            EvidencePriority.HIGH,
            False,
        ),
        (
            EvidenceCategory.RUNTIME_OBSERVATION,
            "Observe the proposed sequence's runtime step for {subject_id}",
            EvidencePriority.HIGH,
            True,
        ),
        (
            EvidenceCategory.MMIO_ACCESS,
            "Resolve the proposed sequence's MMIO step for {subject_id}",
            EvidencePriority.HIGH,
            True,
        ),
        (
            EvidenceCategory.PRIVILEGE_TRANSITION,
            "Resolve the proposed sequence's privilege conditions for {subject_id}",
            EvidencePriority.HIGH,
            False,
        ),
    )
    reasoning_step_template = (
        "AttackChainAgent retained the sequence as a hypothesis for {subject_id}"
    )
