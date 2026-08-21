"""Fixed-order deterministic orchestration for Phase 9B2B mock agents."""

from __future__ import annotations

from typing import ClassVar

from chipchain.agents.attack_chain_agent import AttackChainAgent
from chipchain.agents.base import (
    DETERMINISTIC_MOCK_CONFIDENCE,
    DeterministicMockReasoningAgent,
    ReasoningContext,
    _snapshot_context,
)
from chipchain.agents.code_agent import CodeAgent
from chipchain.agents.hardware_agent import HardwareAgent
from chipchain.agents.vulnerability_agent import VulnerabilityAgent
from chipchain.reasoning.hypothesis import AttackHypothesis
from chipchain.reasoning.reasoning_result import ReasoningResult


class MultiAgentReasoningOrchestrator:
    """Run isolated agents in one fixed order and return reasoning only."""

    agent_classes: ClassVar[
        tuple[type[DeterministicMockReasoningAgent], ...]
    ] = (
        CodeAgent,
        HardwareAgent,
        VulnerabilityAgent,
        AttackChainAgent,
    )

    def reason(self, context: ReasoningContext) -> ReasoningResult:
        """Run all roles once over one detached context snapshot."""

        snapshot = _snapshot_context(context)
        reasoning_steps: list[str] = []
        supporting_evidence_ids: set[str] = set()
        missing_evidence_ids: set[str] = set()
        agent_ids: list[str] = []
        final_hypothesis: AttackHypothesis | None = None
        final_confidence = DETERMINISTIC_MOCK_CONFIDENCE

        for agent_class in self.agent_classes:
            agent = agent_class(snapshot)
            hypothesis = agent.produce_hypothesis()
            requests = agent.request_evidence()
            agent_result = agent.analyze(snapshot)

            for request in requests:
                request.validate_against(hypothesis)
            agent_result.validate_against(hypothesis)
            reasoning_steps.extend(agent_result.reasoning_steps)
            supporting_evidence_ids.update(
                agent_result.supporting_evidence_ids
            )
            missing_evidence_ids.update(agent_result.missing_evidence)
            agent_ids.append(agent.agent_id)
            final_hypothesis = hypothesis
            final_confidence = agent_result.confidence

        if final_hypothesis is None:
            raise RuntimeError("reasoning orchestrator requires at least one agent")
        return ReasoningResult.create(
            final_hypothesis,
            reasoning_steps=reasoning_steps,
            supporting_evidence_ids=sorted(supporting_evidence_ids),
            missing_evidence=sorted(missing_evidence_ids),
            confidence=final_confidence,
            metadata={
                "agent_ids": agent_ids,
                "execution_order": [
                    agent_class.role.value for agent_class in self.agent_classes
                ],
                "reasoning_mode": "deterministic_mock",
                "result_scope": "reasoning_only",
            },
        )
