"""Single-call reasoning orchestration, with no retry, repair or verification."""

from hashlib import sha256

from chipchain.candidates import HardwareTriggerCandidateContext
from chipchain.reasoning.trigger_candidate._json import utf8_snapshot
from chipchain.reasoning.trigger_candidate.contracts import (
    MAX_RESPONSE_BYTES, ReasoningProviderProfile, ReasoningResponseProvenance, TriggerCandidateProposalResult,
)
from chipchain.reasoning.trigger_candidate.errors import ProviderGenerationError, ProposalParseError, ReasoningRequestError
from chipchain.reasoning.trigger_candidate.parser import materialize_trigger_candidate, parse_model_proposal
from chipchain.reasoning.trigger_candidate.prompt import build_reasoning_prompt, build_reasoning_request
from chipchain.reasoning.trigger_candidate.provider import TriggerCandidateReasoningProvider


def propose_trigger_candidate(
    context: HardwareTriggerCandidateContext, provider: TriggerCandidateReasoningProvider,
) -> TriggerCandidateProposalResult:
    """Return only a contract-consistent hypothesis, not a supported truth claim.

    The injected provider is trusted host code; its text is untrusted. This
    package supplies no network/provider implementation and never loads secrets.
    """

    try:
        snapshot = HardwareTriggerCandidateContext.model_validate(context)
    except (ValueError, TypeError, RecursionError):
        raise ReasoningRequestError("candidate context rejected before provider call") from None
    try:
        profile = ReasoningProviderProfile.model_validate(provider.profile)
    except Exception:
        raise ProviderGenerationError("provider profile unavailable or invalid") from None
    request = build_reasoning_request(snapshot, profile)
    # Validate the deterministic prompt contract before invoking the provider.
    # Providers can render this same request with the public prompt builder.
    build_reasoning_prompt(request)
    request_id = request.id
    try:
        raw_response = provider.generate(request)
        after_profile = ReasoningProviderProfile.model_validate(provider.profile)
    except Exception:
        raise ProviderGenerationError("provider generation failed; no retry performed") from None
    if after_profile != profile or request.id != request_id:
        raise ProviderGenerationError("provider changed its declared profile or request")
    try:
        raw_bytes = utf8_snapshot(raw_response, MAX_RESPONSE_BYTES)
    except (ValueError, TypeError):
        raise ProposalParseError("provider response text/byte limit rejected") from None
    proposal = parse_model_proposal(raw_response)
    candidate = materialize_trigger_candidate(proposal, snapshot)
    provenance = ReasoningResponseProvenance(provider_profile_id=profile.provider_profile_id,
        model_id=profile.model_id, request_id=request_id, context_id=snapshot.id,
        raw_response_sha256=sha256(raw_bytes).hexdigest(), raw_response_byte_length=len(raw_bytes))
    return TriggerCandidateProposalResult(disposition=proposal.disposition, candidate=candidate, provenance=provenance)
