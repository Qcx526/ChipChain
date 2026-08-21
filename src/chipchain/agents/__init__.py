"""Provider-independent Phase 9B2B reasoning agent contracts."""

from chipchain.agents.attack_chain_agent import AttackChainAgent
from chipchain.agents.base import (
    ReasoningAgent,
    ReasoningContext,
    reasoning_agent_id,
    reasoning_context_id,
)
from chipchain.agents.code_agent import CodeAgent
from chipchain.agents.coordinator import (
    HypothesisMergeConflict,
    MultiAgentReasoningCoordinator,
)
from chipchain.agents.hardware_agent import HardwareAgent
from chipchain.agents.orchestrator import MultiAgentReasoningOrchestrator
from chipchain.agents.state import (
    COORDINATOR_ID,
    AgentMessage,
    AgentMessageType,
    ReasoningSession,
    agent_message_id,
    reasoning_session_id,
)
from chipchain.agents.vulnerability_agent import VulnerabilityAgent
from chipchain.agents.workflow import AgentWorkflow

__all__ = [
    "AttackChainAgent",
    "AgentMessage",
    "AgentMessageType",
    "AgentWorkflow",
    "COORDINATOR_ID",
    "CodeAgent",
    "HardwareAgent",
    "MultiAgentReasoningOrchestrator",
    "MultiAgentReasoningCoordinator",
    "HypothesisMergeConflict",
    "ReasoningAgent",
    "ReasoningContext",
    "ReasoningSession",
    "VulnerabilityAgent",
    "reasoning_agent_id",
    "agent_message_id",
    "reasoning_context_id",
    "reasoning_session_id",
]
