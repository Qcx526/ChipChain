"""Constrained parser for the Phase 9B2C reduced semantic provider DTO."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, TypeAlias

from pydantic import Field, ValidationError, field_validator

from chipchain.models.common import DomainModel, Identifier, UnitInterval
from chipchain.models.enums import Architecture
from chipchain.reasoning.enums import (
    EvidenceCategory,
    EvidencePriority,
    HypothesisSource,
    ReasoningAgentType,
)
from chipchain.models.cross_layer import CrossLayerInteractionType
from chipchain.reasoning.chain_claim import ModelAuthoredChainClaim
from chipchain.reasoning.errors import LLMOutputValidationError
from chipchain.reasoning.evidence_request import EvidenceRequest
from chipchain.reasoning.hypothesis import AttackHypothesis
from chipchain.reasoning.prompts import reasoning_role_contract
from chipchain.reasoning.reasoning_result import ReasoningResult

if TYPE_CHECKING:
    from chipchain.agents.base import ReasoningContext


ParsedReasoningContracts: TypeAlias = tuple[
    AttackHypothesis,
    list[EvidenceRequest],
    ReasoningResult,
]

_FORBIDDEN_OUTPUT_FIELDS = frozenset(
    {
        "attackchain",
        "attackchainstatus",
        "attackchainverdict",
        "behavioredge",
        "causality",
        "causalitystatus",
        "causalityverdict",
        "evidence",
        "feasibility",
        "interactionstatus",
        "interactionverificationstatus",
        "isverified",
        "score",
        "verdict",
        "verification",
        "verificationrecord",
        "verificationscore",
        "verificationstatus",
        "verified",
        "vulnerabilitystatus",
        "vulnerabilityverdict",
    }
)


class _HypothesisSemanticProposal(DomainModel):
    """Provider-authored hypothesis semantics without trusted bindings."""

    description: Identifier
    confidence: UnitInterval
    chain_claim: _ChainClaimSemanticProposal | None = None


class _ChainClaimSemanticProposal(DomainModel):
    """Provider-authored participant selections without system-owned identity."""

    interaction_type: CrossLayerInteractionType
    initiating_vulnerability_ids: list[Identifier] = Field(default_factory=list)
    target_vulnerability_ids: list[Identifier] = Field(default_factory=list)
    trigger_behavior_ids: list[Identifier] = Field(default_factory=list)
    propagation_behavior_ids: list[Identifier] = Field(default_factory=list)
    affected_execution_ids: list[Identifier] = Field(default_factory=list)
    fault_state_ids: list[Identifier] = Field(default_factory=list)
    hardware_resource_ids: list[Identifier] = Field(default_factory=list)
    security_mechanism_ids: list[Identifier] = Field(default_factory=list)

    @field_validator(
        "initiating_vulnerability_ids",
        "target_vulnerability_ids",
        "trigger_behavior_ids",
        "propagation_behavior_ids",
        "affected_execution_ids",
        "fault_state_ids",
        "hardware_resource_ids",
        "security_mechanism_ids",
    )
    @classmethod
    def normalize_reference_lists(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("provider claim reference IDs must be unique")
        return sorted(values)


class _EvidenceRequestSemanticProposal(DomainModel):
    """Provider-authored request text paired with a role contract by position."""

    required_fact: Identifier


class _ReasoningResultSemanticProposal(DomainModel):
    """Provider-authored reasoning semantics with whitelisted references."""

    reasoning_steps: list[Identifier] = Field(min_length=1)
    supporting_evidence_ids: list[Identifier]
    confidence: UnitInterval

    @field_validator("reasoning_steps", "supporting_evidence_ids")
    @classmethod
    def reject_duplicates(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("reasoning proposal lists must be unique")
        return values


class _ReasoningProviderSemanticOutput(DomainModel):
    """Reduced provider DTO; ChipChain owns context and role bindings."""

    hypothesis: _HypothesisSemanticProposal
    evidence_requests: list[_EvidenceRequestSemanticProposal] = Field(
        min_length=1
    )
    reasoning_result: _ReasoningResultSemanticProposal


def reasoning_provider_output_json_schema() -> dict[str, object]:
    """Return the strict provider schema without changing parser optionality."""

    schema = _ReasoningProviderSemanticOutput.model_json_schema(
        mode="validation"
    )
    normalized = _normalize_strict_provider_schema(schema)
    if not isinstance(normalized, dict):  # pragma: no cover - root is fixed
        raise TypeError("reasoning provider schema root must be an object")
    return normalized


def _normalize_strict_provider_schema(value: object) -> object:
    """Require every declared object property for strict structured output.

    Logical optionality remains encoded by nullable values, while the ordinary
    Pydantic DTO continues to accept omitted defaulted fields for manual and
    legacy parser callers.
    """

    if isinstance(value, dict):
        normalized = {
            key: _normalize_strict_provider_schema(item)
            for key, item in value.items()
        }
        properties = normalized.get("properties")
        if isinstance(properties, dict):
            normalized["required"] = list(properties)
            normalized["additionalProperties"] = False
        return normalized
    if isinstance(value, list):
        return [_normalize_strict_provider_schema(item) for item in value]
    return value


class ConstrainedReasoningOutputParser:
    """Convert strict provider JSON into existing non-verifying contracts."""

    def parse(
        self,
        raw_output: str,
        *,
        context: "ReasoningContext",
        role: ReasoningAgentType | str,
    ) -> ParsedReasoningContracts:
        """Reject unknown truth claims and bind proposals to supplied references."""

        from chipchain.agents.base import ReasoningContext

        if not isinstance(raw_output, str):
            raise LLMOutputValidationError(
                "reasoning provider output must be text",
                stage="response_content",
            )
        if not isinstance(context, ReasoningContext):
            raise TypeError("parser context must be a ReasoningContext")
        snapshot = ReasoningContext.model_validate(context.model_dump(mode="json"))
        normalized_role = ReasoningAgentType(role)
        role_contract = reasoning_role_contract(normalized_role)
        try:
            payload = json.loads(raw_output)
        except json.JSONDecodeError:
            raise LLMOutputValidationError(
                "reasoning provider output is not valid JSON",
                stage="json_parse",
            ) from None
        if not isinstance(payload, dict):
            raise LLMOutputValidationError(
                "reasoning provider output must be one JSON object",
                stage="output_schema",
            )
        _reject_forbidden_fields(payload)
        try:
            proposal = _ReasoningProviderSemanticOutput.model_validate(payload)
        except ValidationError:
            raise LLMOutputValidationError(
                "reasoning provider output violates the constrained schema",
                stage="output_schema",
            ) from None

        if (
            proposal.hypothesis.chain_claim is not None
            and normalized_role is not ReasoningAgentType.ATTACK_CHAIN
        ):
            raise LLMOutputValidationError(
                "only the attack_chain role may author a chain claim",
                stage="role_authority",
            )

        expected_requests = role_contract["evidence_requests"]
        required_evidence_types = [
            EvidenceCategory(item["evidence_type"])
            for item in expected_requests
        ]

        claim = self._parse_chain_claim(
            proposal.hypothesis.chain_claim,
            architecture=snapshot.architecture,
            role=normalized_role,
        )
        hypothesis = AttackHypothesis.create(
            source=HypothesisSource.LLM,
            architecture=snapshot.architecture,
            description=proposal.hypothesis.description,
            affected_components=snapshot.affected_components,
            attack_pattern_reference=snapshot.attack_pattern_reference,
            required_evidence_types=required_evidence_types,
            confidence=proposal.hypothesis.confidence,
            model_authored_chain_claim=claim,
            metadata={
                "confidence_semantics": "reasoning_only_not_verification_score",
                "provider_output": "constrained",
                "reasoning_role": normalized_role.value,
            },
        )
        requests = self._parse_requests(
            proposal.evidence_requests,
            hypothesis=hypothesis,
            context=snapshot,
            expected_requests=expected_requests,
            role=normalized_role,
        )
        unknown_evidence_ids = set(
            proposal.reasoning_result.supporting_evidence_ids
        ).difference(snapshot.available_evidence_ids)
        if unknown_evidence_ids:
            raise LLMOutputValidationError(
                "reasoning result cites evidence outside reasoning context",
                stage="evidence_reference",
            )
        result = ReasoningResult.create(
            hypothesis,
            reasoning_steps=proposal.reasoning_result.reasoning_steps,
            supporting_evidence_ids=(
                proposal.reasoning_result.supporting_evidence_ids
            ),
            missing_evidence=[request.id for request in requests],
            confidence=proposal.reasoning_result.confidence,
            metadata={
                "confidence_semantics": "reasoning_only_not_verification_score",
                "provider_output": "constrained",
                "reasoning_role": normalized_role.value,
            },
        )
        return hypothesis, requests, result

    @staticmethod
    def _parse_chain_claim(
        proposal: _ChainClaimSemanticProposal | None,
        *,
        architecture: Architecture,
        role: ReasoningAgentType,
    ) -> ModelAuthoredChainClaim | None:
        if proposal is None:
            return None
        values = proposal.model_dump(mode="python")
        return ModelAuthoredChainClaim.create(
            architecture=architecture,
            author_role=role,
            metadata={
                "authorship_semantics": "model_proposal_not_verified_truth",
                "provider_output": "constrained",
                "reasoning_role": role.value,
            },
            **values,
        )

    def _parse_requests(
        self,
        proposals: list[_EvidenceRequestSemanticProposal],
        *,
        hypothesis: AttackHypothesis,
        context: "ReasoningContext",
        expected_requests: list[dict[str, object]],
        role: ReasoningAgentType,
    ) -> list[EvidenceRequest]:
        if len(proposals) != len(expected_requests):
            raise LLMOutputValidationError(
                "evidence requests violate role contract cardinality",
                stage="request_cardinality",
            )
        requests: list[EvidenceRequest] = []
        for proposal, request_contract in zip(
            proposals,
            expected_requests,
            strict=True,
        ):
            permits_trigger = bool(
                request_contract["use_dynamic_trigger_reference"]
            )
            requests.append(
                EvidenceRequest.create(
                    hypothesis,
                    evidence_type=EvidenceCategory(
                        request_contract["evidence_type"]
                    ),
                    required_fact=proposal.required_fact,
                    dynamic_trigger_fact_reference=(
                        context.dynamic_trigger_fact_reference
                        if permits_trigger
                        else None
                    ),
                    priority=EvidencePriority(request_contract["priority"]),
                    metadata={
                        "provider_output": "constrained",
                        "reasoning_role": role.value,
                    },
                )
            )
        return requests


def _reject_forbidden_fields(payload: object) -> None:
    if isinstance(payload, dict):
        for key, nested in payload.items():
            normalized_key = "".join(
                character
                for character in str(key).lower()
                if character.isalnum()
            )
            if normalized_key in _FORBIDDEN_OUTPUT_FIELDS:
                raise LLMOutputValidationError(
                    "reasoning provider output contains a forbidden truth field",
                    stage="forbidden_truth_field",
                )
            _reject_forbidden_fields(nested)
    elif isinstance(payload, list):
        for nested in payload:
            _reject_forbidden_fields(nested)
