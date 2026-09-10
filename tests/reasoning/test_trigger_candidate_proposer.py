"""Deterministic fake-provider paths; never invoke an external model."""

from hashlib import sha256
import json

import pytest

from chipchain.candidates import validate_trigger_candidate
from chipchain.reasoning.trigger_candidate import (
    CandidateMaterializationError, ProposalParseError, ProviderGenerationError, ReasoningProviderProfile,
    ReasoningRequestError, TriggerCandidateProposalResult, build_reasoning_prompt, propose_trigger_candidate,
)


class DeterministicFakeProvider:
    """Fixed benign response/failure, plus call accounting only for tests."""

    def __init__(self, profile, response, *, fail=False):
        self.profile = profile
        self.response = response
        self.fail = fail
        self.requests = []

    def generate(self, request):
        self.requests.append(request)
        assert json.loads(build_reasoning_prompt(request))["request_id"] == request.id
        if self.fail:
            raise RuntimeError("private synthetic provider error payload")
        return self.response


def test_fake_provider_determinism_exact_provenance_and_no_source_changes(context, provider_profile, proposal_payload):
    original = context.model_dump_json()
    raw = json.dumps(proposal_payload, indent=2)
    provider = DeterministicFakeProvider(provider_profile, raw)
    first = propose_trigger_candidate(context, provider)
    second = propose_trigger_candidate(context, provider)
    assert first == second and first.id == second.id
    assert len(provider.requests) == 2 and provider.requests[0].id == provider.requests[1].id
    assert first.provenance.request_id == provider.requests[0].id
    assert first.provenance.provider_profile_id == provider_profile.provider_profile_id
    assert first.provenance.model_id == provider_profile.model_id
    assert first.provenance.raw_response_sha256 == sha256(raw.encode()).hexdigest()
    assert first.provenance.raw_response_byte_length == len(raw.encode())
    assert first.candidate.status == "HYPOTHESIS" and first.disposition == "PROPOSE"
    assert original == context.model_dump_json()
    assert TriggerCandidateProposalResult.model_validate_json(first.model_dump_json()).id == first.id
    assert "raw_response" not in first.candidate.model_dump_json()
    assert "raw_response_text" not in first.model_dump_json()


def test_semantically_equal_raw_json_keeps_candidate_but_not_raw_hash(context, provider_profile, proposal_payload):
    compact = propose_trigger_candidate(context, DeterministicFakeProvider(provider_profile, json.dumps(proposal_payload, separators=(",", ":"))))
    spaced = propose_trigger_candidate(context, DeterministicFakeProvider(provider_profile, json.dumps(proposal_payload, indent=2)))
    assert compact.candidate.id == spaced.candidate.id
    assert compact.provenance.request_id == spaced.provenance.request_id
    assert compact.provenance.raw_response_sha256 != spaced.provenance.raw_response_sha256


@pytest.mark.parametrize("raw", ["broken JSON", "{}", "{}\n{}", b"{}", None, "x" * 65537, "😀" * 20000])
def test_invalid_and_oversize_fake_outputs_have_no_fallback(context, provider_profile, raw):
    provider = DeterministicFakeProvider(provider_profile, raw)
    with pytest.raises(ProposalParseError):
        propose_trigger_candidate(context, provider)
    assert len(provider.requests) == 1


def test_utf8_byte_limit_checked_before_parser(context, provider_profile, monkeypatch):
    def forbidden(*args):
        pytest.fail("oversize UTF-8 must not reach parser")
    monkeypatch.setattr("chipchain.reasoning.trigger_candidate.proposer.parse_model_proposal", forbidden)
    with pytest.raises(ProposalParseError):
        propose_trigger_candidate(context, DeterministicFakeProvider(provider_profile, "😀" * 20000))


def test_provider_exception_sanitized_and_not_retried(context, provider_profile):
    provider = DeterministicFakeProvider(provider_profile, "", fail=True)
    with pytest.raises(ProviderGenerationError) as error:
        propose_trigger_candidate(context, provider)
    assert "private synthetic" not in str(error.value)
    assert len(provider.requests) == 1


def test_bad_context_fails_before_provider_call(context, provider_profile):
    provider = DeterministicFakeProvider(provider_profile, "")
    with pytest.raises(ReasoningRequestError):
        propose_trigger_candidate(context.model_copy(update={"si_sha256": "0" * 64}), provider)
    assert provider.requests == []


def test_invalid_provider_profile_fails_before_generate(context, provider_profile):
    provider = DeterministicFakeProvider(provider_profile.model_copy(update={"provider_profile_id": "/tmp/profile"}), "")
    with pytest.raises(ProviderGenerationError):
        propose_trigger_candidate(context, provider)
    assert provider.requests == []


def test_provider_profile_drift_is_not_silent_provenance(context, provider_profile, abstain_payload):
    class DriftingProvider(DeterministicFakeProvider):
        def generate(self, request):
            response = super().generate(request)
            self.profile = ReasoningProviderProfile(provider_profile_id="different-provider", model_id=None)
            return response
    provider = DriftingProvider(provider_profile, json.dumps(abstain_payload))
    with pytest.raises(ProviderGenerationError):
        propose_trigger_candidate(context, provider)
    assert len(provider.requests) == 1


def test_provider_cannot_mutate_request_identity(context, provider_profile, abstain_payload):
    class MutatingProvider(DeterministicFakeProvider):
        def generate(self, request):
            response = super().generate(request)
            object.__setattr__(request, "context_payload_sha256", "0" * 64)
            return response
    provider = MutatingProvider(provider_profile, json.dumps(abstain_payload))
    with pytest.raises(ProviderGenerationError):
        propose_trigger_candidate(context, provider)
    assert len(provider.requests) == 1


@pytest.mark.parametrize("abstain", [False, True])
def test_frozen_candidate_validator_is_mandatory(context, provider_profile, proposal_payload, abstain_payload, monkeypatch, abstain):
    calls = []
    def checked(candidate, supplied_context):
        calls.append(candidate.id)
        return validate_trigger_candidate(candidate, supplied_context)
    monkeypatch.setattr("chipchain.reasoning.trigger_candidate.parser.validate_trigger_candidate", checked)
    payload = abstain_payload if abstain else proposal_payload
    result = propose_trigger_candidate(context, DeterministicFakeProvider(provider_profile, json.dumps(payload)))
    assert calls == [result.candidate.id]
    def rejected(*args):
        raise ValueError("synthetic final-validator rejection")
    monkeypatch.setattr("chipchain.reasoning.trigger_candidate.parser.validate_trigger_candidate", rejected)
    with pytest.raises(CandidateMaterializationError):
        propose_trigger_candidate(context, DeterministicFakeProvider(provider_profile, json.dumps(payload)))


def test_abstain_is_explicit_not_verified_negative(context, provider_profile, abstain_payload):
    result = propose_trigger_candidate(context, DeterministicFakeProvider(provider_profile, json.dumps(abstain_payload)))
    assert result.disposition == "ABSTAIN" and result.candidate.status == "HYPOTHESIS"
    assert not result.candidate.evidence_bindings
    assert set(result.candidate.unresolved_condition_ids) == {c.id for c in context.unresolved_conditions}


@pytest.mark.parametrize("field", ["verified", "truth_score", "confidence", "vulnerability", "cause", "necessary", "sufficient"])
def test_result_and_provenance_cannot_carry_verdicts(context, provider_profile, abstain_payload, field):
    result = propose_trigger_candidate(context, DeterministicFakeProvider(provider_profile, json.dumps(abstain_payload)))
    with pytest.raises(ValueError):
        TriggerCandidateProposalResult.model_validate(dict(result.model_dump(), **{field: True}))
    with pytest.raises(ValueError):
        type(result.provenance).model_validate(dict(result.provenance.model_dump(), **{field: True}))
