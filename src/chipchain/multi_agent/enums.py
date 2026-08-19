"""Closed Phase 8 role and non-verification status vocabularies."""

from __future__ import annotations

from enum import Enum


class AgentRole(str, Enum):
    """The only roles executed by the Phase 8 coordinator."""

    EVIDENCE_ANALYST = "evidence_analyst"
    SECURITY_REASONER = "security_reasoner"
    CRITIC = "critic"


class EvidenceAnalysisStatus(str, Enum):
    """Evidence inventory status without truth verification semantics."""

    CONTEXT_READY = "context_ready"
    EVIDENCE_INCOMPLETE = "evidence_incomplete"
    CONTEXT_INCONSISTENT = "context_inconsistent"


class CriticReviewStatus(str, Enum):
    """Review disposition that cannot approve or verify a vulnerability."""

    REVIEW_COMPLETE = "review_complete"
    REVISION_REQUIRED = "revision_required"
    CONTEXT_CONFLICT = "context_conflict"


class AgentExecutionStatus(str, Enum):
    """Deterministic execution outcome for one fixed role."""

    COMPLETED = "completed"
    FAILED = "failed"
