"""Hardware-side hypothesis contracts and bounded evidence context, not verification."""

from chipchain.candidates.context import build_trigger_candidate_context, candidate_context_view, serialize_candidate_context
from chipchain.candidates.enums import CandidateEpistemicStatus, CandidateStatus, CandidateSupportKind, ObjectiveFactKind, UnresolvedConditionKind
from chipchain.candidates.facts import HardwareTriggerCandidateContext, ObjectiveFactReference, UnresolvedCondition
from chipchain.candidates.models import CandidateRationaleAtom, CandidateRequirementSupport, HardwareTriggerCandidate
from chipchain.candidates.validation import validate_trigger_candidate

__all__ = [
    "build_trigger_candidate_context", "candidate_context_view", "serialize_candidate_context",
    "CandidateEpistemicStatus", "CandidateStatus", "CandidateSupportKind", "ObjectiveFactKind",
    "UnresolvedConditionKind", "HardwareTriggerCandidateContext", "ObjectiveFactReference",
    "UnresolvedCondition", "CandidateRationaleAtom", "CandidateRequirementSupport",
    "HardwareTriggerCandidate", "validate_trigger_candidate",
]
