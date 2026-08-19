"""Three fixed typed agents backed by one reusable structured-output transport."""

from __future__ import annotations

from chipchain.multi_agent.models import (
    CriticReview,
    EvidenceAnalysis,
    MultiAgentContext,
    SecurityReasoningAssessment,
)
from chipchain.multi_agent.prompts import (
    CriticPromptBuilder,
    EvidenceAnalystPromptBuilder,
    SecurityReasonerPromptBuilder,
)
from chipchain.reasoning import StructuredOutputProvider, StructuredPromptRequest


class EvidenceAnalystAgent:
    """Inventory existing evidence and gaps without verifying either."""

    def __init__(
        self,
        provider: StructuredOutputProvider,
        prompt_builder: EvidenceAnalystPromptBuilder | None = None,
    ) -> None:
        self._provider = provider
        self._prompt_builder = prompt_builder or EvidenceAnalystPromptBuilder()

    def prepare(self, context: MultiAgentContext) -> StructuredPromptRequest:
        """Build the deterministic role-specific request."""

        return self._prompt_builder.build(context)

    def execute(self, request: StructuredPromptRequest) -> EvidenceAnalysis:
        """Return one strict evidence inventory from the configured provider."""

        return self._provider.generate_structured(request, EvidenceAnalysis)


class SecurityReasoningAgent:
    """Generate cited, explicitly unverified semantic hypotheses."""

    def __init__(
        self,
        provider: StructuredOutputProvider,
        prompt_builder: SecurityReasonerPromptBuilder | None = None,
    ) -> None:
        self._provider = provider
        self._prompt_builder = prompt_builder or SecurityReasonerPromptBuilder()

    def prepare(
        self,
        context: MultiAgentContext,
        evidence_analysis: EvidenceAnalysis,
    ) -> StructuredPromptRequest:
        """Build a request that labels prior output as analysis, not evidence."""

        return self._prompt_builder.build(context, evidence_analysis)

    def execute(
        self,
        request: StructuredPromptRequest,
    ) -> SecurityReasoningAssessment:
        """Return one strict semantic assessment from the configured provider."""

        return self._provider.generate_structured(
            request,
            SecurityReasoningAssessment,
        )


class CriticAgent:
    """Review prior analyses without changing them or adding domain facts."""

    def __init__(
        self,
        provider: StructuredOutputProvider,
        prompt_builder: CriticPromptBuilder | None = None,
    ) -> None:
        self._provider = provider
        self._prompt_builder = prompt_builder or CriticPromptBuilder()

    def prepare(
        self,
        context: MultiAgentContext,
        evidence_analysis: EvidenceAnalysis,
        security_reasoning: SecurityReasoningAssessment,
    ) -> StructuredPromptRequest:
        """Build a request that preserves both prior structured outputs."""

        return self._prompt_builder.build(
            context,
            evidence_analysis,
            security_reasoning,
        )

    def execute(self, request: StructuredPromptRequest) -> CriticReview:
        """Return one strict review from the configured provider."""

        return self._provider.generate_structured(request, CriticReview)
