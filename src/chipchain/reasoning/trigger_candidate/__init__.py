"""Offline-testable LLM proposal boundary; accepted outputs remain hypotheses."""

from chipchain.reasoning.trigger_candidate.contracts import (
    ModelTriggerCandidateProposal, ReasoningProviderProfile, ReasoningResponseProvenance,
    TriggerCandidateProposalResult, TriggerCandidateReasoningRequest,
)
from chipchain.reasoning.trigger_candidate.errors import (
    CandidateMaterializationError, ProposalParseError, ProviderGenerationError,
    ReasoningRequestError, TriggerCandidateReasoningError,
)
from chipchain.reasoning.trigger_candidate.parser import materialize_trigger_candidate, parse_model_proposal
from chipchain.reasoning.trigger_candidate.prompt import build_reasoning_prompt, build_reasoning_request
from chipchain.reasoning.trigger_candidate.proposer import propose_trigger_candidate
from chipchain.reasoning.trigger_candidate.provider import TriggerCandidateReasoningProvider

__all__ = [
    "ModelTriggerCandidateProposal", "ReasoningProviderProfile", "ReasoningResponseProvenance",
    "TriggerCandidateProposalResult", "TriggerCandidateReasoningRequest", "CandidateMaterializationError",
    "ProposalParseError", "ProviderGenerationError", "ReasoningRequestError", "TriggerCandidateReasoningError",
    "materialize_trigger_candidate", "parse_model_proposal", "build_reasoning_prompt", "build_reasoning_request",
    "propose_trigger_candidate", "TriggerCandidateReasoningProvider",
]
