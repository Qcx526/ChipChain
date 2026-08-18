"""Stable enums for Phase 7 retrieval and semantic interpretation."""

from __future__ import annotations

from enum import Enum


class ArchitectureKnowledgeScope(str, Enum):
    """Whether a document is architecture-specific or explicitly global."""

    ARCHITECTURE = "architecture"
    GLOBAL = "global"


class CandidateSemanticStatus(str, Enum):
    """Non-verifying semantic outcomes permitted in Phase 7."""

    REQUIRES_VERIFICATION = "requires_verification"
    INSUFFICIENT_CONTEXT = "insufficient_context"
    CONTEXTUALLY_INCONSISTENT = "contextually_inconsistent"


class LLMAPIStyle(str, Enum):
    """Explicit OpenAI-compatible transport styles."""

    RESPONSES = "responses"
    CHAT_COMPLETIONS = "chat_completions"
