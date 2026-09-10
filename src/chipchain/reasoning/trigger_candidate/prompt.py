"""Deterministic request and role/data-separated JSON prompt; no provider SDK."""

from hashlib import sha256

from chipchain.core import canonical_json_bytes
from chipchain.candidates import HardwareTriggerCandidateContext
from chipchain.reasoning.trigger_candidate._json import strict_json_object
from chipchain.reasoning.trigger_candidate.contracts import (
    MAX_CONTEXT_PAYLOAD_BYTES, ReasoningProviderProfile, TriggerCandidateReasoningRequest,
    _context_payload, _schema_json,
)
from chipchain.reasoning.trigger_candidate.errors import ReasoningRequestError


def build_reasoning_request(
    context: HardwareTriggerCandidateContext, provider: ReasoningProviderProfile,
) -> TriggerCandidateReasoningRequest:
    """Bind exact frozen compact context, reference indices and fixed v1 rules."""

    try:
        snapshot = HardwareTriggerCandidateContext.model_validate(context)
        profile = ReasoningProviderProfile.model_validate(provider)
        payload = _context_payload(snapshot)
        return TriggerCandidateReasoningRequest(provider=profile, context_id=snapshot.id,
            context_payload_json=payload, context_payload_sha256=sha256(payload.encode("utf-8")).hexdigest(),
            response_schema_json=_schema_json())
    except (ValueError, TypeError, RecursionError):
        raise ReasoningRequestError("reasoning request/context rejected") from None


def build_reasoning_prompt(request: TriggerCandidateReasoningRequest) -> str:
    """Keep immutable system instructions separate from JSON-escaped untrusted data.

    This envelope is not an HTTP body or a claim to prevent all model-level
    prompt injection. Strict output validation remains mandatory.
    """

    try:
        snapshot = TriggerCandidateReasoningRequest.model_validate(request)
        envelope = {
            "request_id": snapshot.id,
            "system_instructions": snapshot.task_instructions,
            "output_schema": strict_json_object(snapshot.response_schema_json, limit=65536),
            "untrusted_context_data": strict_json_object(snapshot.context_payload_json, limit=MAX_CONTEXT_PAYLOAD_BYTES),
        }
        return canonical_json_bytes(envelope).decode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise ReasoningRequestError("reasoning prompt request rejected") from None
