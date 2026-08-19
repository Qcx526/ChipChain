"""Public typed collaborative reasoning API for ChipChain Phase 8."""

from chipchain.multi_agent.agents import (
    CriticAgent,
    EvidenceAnalystAgent,
    SecurityReasoningAgent,
)
from chipchain.multi_agent.coordinator import (
    MultiAgentCoordinator,
    determine_final_semantic_status,
)
from chipchain.multi_agent.enums import (
    AgentExecutionStatus,
    AgentRole,
    CriticReviewStatus,
    EvidenceAnalysisStatus,
)
from chipchain.multi_agent.errors import (
    AgentExecutionError,
    AgentOutputValidationError,
)
from chipchain.multi_agent.mock_provider import MockStructuredOutputProvider
from chipchain.multi_agent.models import (
    AgentExecutionRecord,
    CriticReview,
    EvidenceAnalysis,
    MultiAgentContext,
    MultiAgentReasoningResult,
    SecurityReasoningAssessment,
    SemanticHypothesis,
)
from chipchain.multi_agent.prompts import (
    CriticPromptBuilder,
    EvidenceAnalystPromptBuilder,
    SecurityReasonerPromptBuilder,
)

__all__ = [
    "AgentExecutionError",
    "AgentExecutionRecord",
    "AgentExecutionStatus",
    "AgentOutputValidationError",
    "AgentRole",
    "CriticAgent",
    "CriticPromptBuilder",
    "CriticReview",
    "CriticReviewStatus",
    "EvidenceAnalysis",
    "EvidenceAnalysisStatus",
    "EvidenceAnalystAgent",
    "EvidenceAnalystPromptBuilder",
    "MockStructuredOutputProvider",
    "MultiAgentContext",
    "MultiAgentCoordinator",
    "MultiAgentReasoningResult",
    "SecurityReasonerPromptBuilder",
    "SecurityReasoningAgent",
    "SecurityReasoningAssessment",
    "SemanticHypothesis",
    "determine_final_semantic_status",
]
