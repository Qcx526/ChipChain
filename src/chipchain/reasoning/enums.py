"""Stable enums for retrieval, semantic interpretation, and reasoning contracts."""

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


class ProviderCompletionState(str, Enum):
    """Bounded Responses completion states retained without vendor payloads."""

    INCOMPLETE = "incomplete"
    FAILED = "failed"
    NONTERMINAL_OR_UNKNOWN = "nonterminal_or_unknown"


class ProviderIncompleteReason(str, Enum):
    """Closed incomplete reasons accepted from a Responses transport."""

    MAX_OUTPUT_TOKENS = "max_output_tokens"
    CONTENT_FILTER = "content_filter"
    OTHER_BOUNDED_INCOMPLETE_REASON = "other_bounded_incomplete_reason"


class HypothesisSource(str, Enum):
    """Permitted provenance categories for an unverified hypothesis."""

    LLM = "llm"
    CVE = "cve"
    CWE = "cwe"
    CAPEC = "capec"
    ANALYST = "analyst"


class EvidenceCategory(str, Enum):
    """Evidence categories that a reasoning contract may request by reference."""

    STATIC_BEHAVIOR = "static_behavior"
    RUNTIME_OBSERVATION = "runtime_observation"
    MMIO_ACCESS = "mmio_access"
    PRIVILEGE_TRANSITION = "privilege_transition"


class EvidencePriority(str, Enum):
    """Advisory collection priority without verification semantics."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReasoningAgentType(str, Enum):
    """Closed interface roles for future Phase 9B2B agent implementations."""

    HYPOTHESIS_GENERATOR = "hypothesis_generator"
    EVIDENCE_ANALYST = "evidence_analyst"
    SECURITY_REASONER = "security_reasoner"
    CRITIC = "critic"
    CODE = "code"
    HARDWARE = "hardware"
    VULNERABILITY = "vulnerability"
    ATTACK_CHAIN = "attack_chain"


class ReasoningPromptVisibility(str, Enum):
    """Opt-in model-visible context policy for Phase 10C ablations."""

    FULL_CONTEXT = "full_context"
    MASKED_CHAIN_CONTEXT = "masked_chain_context"
