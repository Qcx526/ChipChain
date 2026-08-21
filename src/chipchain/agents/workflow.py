"""Fixed Phase 9B2B multi-agent reasoning workflow."""

from __future__ import annotations

from collections.abc import Iterable
from typing import ClassVar

from chipchain.agents.attack_chain_agent import AttackChainAgent
from chipchain.agents.base import (
    DeterministicMockReasoningAgent,
    ReasoningContext,
)
from chipchain.agents.code_agent import CodeAgent
from chipchain.agents.coordinator import MultiAgentReasoningCoordinator
from chipchain.agents.hardware_agent import HardwareAgent
from chipchain.agents.state import ReasoningSession
from chipchain.agents.vulnerability_agent import VulnerabilityAgent
from chipchain.reasoning.enums import ReasoningAgentType
from chipchain.reasoning.feedback import EvidenceFeedback


class AgentWorkflow:
    """Execute the four roles in a fixed deterministic reasoning-only order."""

    contract: ClassVar[str] = "phase9b2b_multi_agent_workflow_v1"
    agent_classes: ClassVar[
        tuple[type[DeterministicMockReasoningAgent], ...]
    ] = (
        CodeAgent,
        HardwareAgent,
        VulnerabilityAgent,
        AttackChainAgent,
    )
    hypothesis_only_roles: ClassVar[frozenset[ReasoningAgentType]] = frozenset(
        {ReasoningAgentType.ATTACK_CHAIN}
    )

    def __init__(
        self,
        *,
        coordinator: MultiAgentReasoningCoordinator | None = None,
    ) -> None:
        self._coordinator = coordinator or MultiAgentReasoningCoordinator()

    def is_hypothesis_only(
        self, agent_type: ReasoningAgentType | str
    ) -> bool:
        """Return whether a role is prohibited from emitting requests/results."""

        return ReasoningAgentType(agent_type) in self.hypothesis_only_roles

    def execute(self, context: ReasoningContext) -> ReasoningSession:
        """Run the fixed workflow and return deterministic session state."""

        return self._coordinator.coordinate(context, self)

    def propagate_feedback(
        self,
        session: ReasoningSession,
        feedbacks: Iterable[EvidenceFeedback],
    ) -> ReasoningSession:
        """Route feedback through the coordinator without invoking agents again."""

        return self._coordinator.propagate_feedback(session, feedbacks)
