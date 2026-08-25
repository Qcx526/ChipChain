"""Bounded Phase 9B2B reasoning-engine contract."""

from __future__ import annotations

from typing import TYPE_CHECKING

from chipchain.reasoning.enums import (
    ReasoningAgentType,
    ReasoningPromptVisibility,
)
from chipchain.reasoning.parser import (
    ConstrainedReasoningOutputParser,
    ParsedReasoningContracts,
)
from chipchain.reasoning.prompts import RoleBasedReasoningPromptBuilder
from chipchain.reasoning.provider import ReasoningProvider

if TYPE_CHECKING:
    from chipchain.agents.base import ReasoningContext


class ReasoningEngine:
    """Run prompt → provider → parser without creating domain truth."""

    def __init__(
        self,
        *,
        provider: ReasoningProvider,
        prompt_builder: RoleBasedReasoningPromptBuilder | None = None,
        parser: ConstrainedReasoningOutputParser | None = None,
        prompt_visibility: ReasoningPromptVisibility | str = (
            ReasoningPromptVisibility.FULL_CONTEXT
        ),
    ) -> None:
        if not isinstance(provider, ReasoningProvider):
            raise TypeError("reasoning engine requires a ReasoningProvider")
        self._provider = provider
        self._prompt_builder = prompt_builder or RoleBasedReasoningPromptBuilder()
        self._parser = parser or ConstrainedReasoningOutputParser()
        self._prompt_visibility = ReasoningPromptVisibility(prompt_visibility)

    def reason(
        self,
        context: "ReasoningContext",
        *,
        role: ReasoningAgentType | str,
    ) -> ParsedReasoningContracts:
        """Return only Hypothesis, EvidenceRequest, and ReasoningResult contracts."""

        prompt = self._prompt_builder.build(
            context,
            role=role,
            visibility=self._prompt_visibility,
        )
        raw_output = self._provider.generate(prompt)
        return self._parser.parse(raw_output, context=context, role=role)
