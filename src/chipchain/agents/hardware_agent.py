"""Deterministic hardware-focused reasoning contract agent."""

from chipchain.agents.base import DeterministicMockReasoningAgent
from chipchain.reasoning.enums import (
    EvidenceCategory,
    EvidencePriority,
    ReasoningAgentType,
)


class HardwareAgent(DeterministicMockReasoningAgent):
    """Reason about referenced MMIO behavior without inferring hardware truth."""

    role = ReasoningAgentType.HARDWARE
    hypothesis_template = (
        "Hardware interaction for {subject_id} may require MMIO corroboration"
    )
    evidence_types = (
        EvidenceCategory.MMIO_ACCESS,
        EvidenceCategory.RUNTIME_OBSERVATION,
    )
    evidence_request_specs = (
        (
            EvidenceCategory.MMIO_ACCESS,
            "Resolve the MMIO access attributes for {subject_id}",
            EvidencePriority.HIGH,
            True,
        ),
        (
            EvidenceCategory.RUNTIME_OBSERVATION,
            "Observe the hardware-facing event for {subject_id}",
            EvidencePriority.HIGH,
            True,
        ),
    )
    reasoning_step_template = (
        "HardwareAgent considered MMIO and runtime references for {subject_id}"
    )
