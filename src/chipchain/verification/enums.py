"""Closed deterministic status enums for Phase 9A verification."""

from __future__ import annotations

from enum import Enum


class VerificationStatus(str, Enum):
    """Outcome of one objective fact check."""

    VERIFIED = "verified"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class ConditionStatus(str, Enum):
    """Outcome of checking a required trigger or precondition."""

    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"
    UNKNOWN = "unknown"


class CandidateVerificationStatus(str, Enum):
    """Objective verification state, separate from semantic reasoning state."""

    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    REJECTED = "rejected"


class VerificationSubjectKind(str, Enum):
    """Subjects supported by the Phase 9A record contract."""

    BEHAVIOR_EDGE = "behavior_edge"
    ENTITY_LINK = "entity_link"
    KNOWLEDGE_EDGE = "knowledge_edge"
    ARCHITECTURE_RULE = "architecture_rule"
    TRIGGER = "trigger"
    PRECONDITION = "precondition"


class ConditionKind(str, Enum):
    """Knowledge-condition categories assessed without probability."""

    TRIGGER = "trigger"
    PRECONDITION = "precondition"


class RootCauseLocalizationStatus(str, Enum):
    """Conservative status for a binary localization candidate."""

    LOCALIZED_CANDIDATE = "localized_candidate"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONTRADICTORY_CONTEXT = "contradictory_context"

