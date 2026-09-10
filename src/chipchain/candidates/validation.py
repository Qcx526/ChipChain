"""Deterministic proposal/reference consistency only, not trigger verification."""

from chipchain.candidates.facts import HardwareTriggerCandidateContext, ObjectiveFactReference
from chipchain.candidates.models import HardwareTriggerCandidate


def validate_trigger_candidate(
    candidate: HardwareTriggerCandidate, context: HardwareTriggerCandidateContext,
) -> HardwareTriggerCandidate:
    """Return a detached hypothesis after exact-context and reference validation.

    Successful validation means contractual consistency only. No score, evidence,
    satisfied requirement or verification record is produced.
    """

    context = HardwareTriggerCandidateContext.model_validate(context)
    candidate = HardwareTriggerCandidate.model_validate(candidate)
    if candidate.context_id != context.id:
        raise ValueError("candidate belongs to another context snapshot")
    if candidate.proposed_requirements.source != context.source:
        raise ValueError("candidate source/architecture differs from context")
    available = context.fact_index()

    def require(ref: ObjectiveFactReference) -> None:
        if ref not in available:
            raise ValueError("objective reference ID/kind/source/scope is outside context")

    for support in candidate.evidence_bindings:
        for ref in support.evidence_refs:
            require(ref)
    for atom in candidate.rationale_atoms:
        for ref in atom.supporting_evidence_refs:
            require(ref)
    if set(candidate.unresolved_condition_ids) != {c.id for c in context.unresolved_conditions}:
        raise ValueError("candidate must retain all and only the context's unresolved conditions")
    return candidate
