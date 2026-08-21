"""Constrained parser for Phase 9B2B reasoning-provider output."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, TypeAlias

from pydantic import Field, ValidationError, field_validator

from chipchain.models.common import DomainModel, Identifier, UnitInterval
from chipchain.reasoning.enums import (
    EvidenceCategory,
    EvidencePriority,
    HypothesisSource,
    ReasoningAgentType,
)
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


class _HypothesisProposal(DomainModel):
    description: Identifier
    affected_components: list[Identifier] = Field(min_length=1)
    attack_pattern_reference: Identifier | None = None
    required_evidence_types: list[EvidenceCategory] = Field(min_length=1)
    confidence: UnitInterval

    @field_validator("affected_components", "required_evidence_types")
    @classmethod
    def reject_duplicates(cls, values: list[object]) -> list[object]:
        if len(values) != len(set(values)):
            raise ValueError("hypothesis proposal lists must be unique")
        return values


class _EvidenceRequestProposal(DomainModel):
    evidence_type: EvidenceCategory
    required_fact: Identifier
    dynamic_trigger_fact_reference: Identifier | None = None
    priority: EvidencePriority


class _ReasoningResultProposal(DomainModel):
    reasoning_steps: list[Identifier] = Field(min_length=1)
    supporting_evidence_ids: list[Identifier] = Field(default_factory=list)
    confidence: UnitInterval

    @field_validator("reasoning_steps", "supporting_evidence_ids")
    @classmethod
    def reject_duplicates(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("reasoning proposal lists must be unique")
        return values


class _ReasoningProviderOutput(DomainModel):
    hypothesis: _HypothesisProposal
    evidence_requests: list[_EvidenceRequestProposal] = Field(min_length=1)
    reasoning_result: _ReasoningResultProposal


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
            raise LLMOutputValidationError("reasoning provider output must be text")
        if not isinstance(context, ReasoningContext):
            raise TypeError("parser context must be a ReasoningContext")
        snapshot = ReasoningContext.model_validate(context.model_dump(mode="json"))
        normalized_role = ReasoningAgentType(role)
        role_contract = reasoning_role_contract(normalized_role)
        try:
            payload = json.loads(raw_output)
        except json.JSONDecodeError:
            raise LLMOutputValidationError(
                "reasoning provider output is not valid JSON"
            ) from None
        if not isinstance(payload, dict):
            raise LLMOutputValidationError(
                "reasoning provider output must be one JSON object"
            )
        _reject_forbidden_fields(payload)
        try:
            proposal = _ReasoningProviderOutput.model_validate(payload)
        except ValidationError:
            raise LLMOutputValidationError(
                "reasoning provider output violates the constrained schema"
            ) from None

        expected_requests = {
            EvidenceCategory(item["evidence_type"]): item
            for item in role_contract["evidence_requests"]
        }
        proposed_types = proposal.hypothesis.required_evidence_types
        if set(proposed_types) != set(expected_requests):
            raise LLMOutputValidationError(
                "hypothesis evidence categories violate role isolation"
            )
        if sorted(proposal.hypothesis.affected_components) != (
            snapshot.affected_components
        ):
            raise LLMOutputValidationError(
                "hypothesis affected components are outside reasoning context"
            )
        if (
            proposal.hypothesis.attack_pattern_reference
            != snapshot.attack_pattern_reference
        ):
            raise LLMOutputValidationError(
                "hypothesis attack-pattern reference mismatch"
            )

        hypothesis = AttackHypothesis.create(
            source=HypothesisSource.LLM,
            architecture=snapshot.architecture,
            description=proposal.hypothesis.description,
            affected_components=proposal.hypothesis.affected_components,
            attack_pattern_reference=(
                proposal.hypothesis.attack_pattern_reference
            ),
            required_evidence_types=proposed_types,
            confidence=proposal.hypothesis.confidence,
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
                "reasoning result cites evidence outside reasoning context"
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

    def _parse_requests(
        self,
        proposals: list[_EvidenceRequestProposal],
        *,
        hypothesis: AttackHypothesis,
        context: "ReasoningContext",
        expected_requests: dict[EvidenceCategory, dict[str, object]],
        role: ReasoningAgentType,
    ) -> list[EvidenceRequest]:
        if len(proposals) != len(expected_requests):
            raise LLMOutputValidationError(
                "evidence requests violate role contract cardinality"
            )
        proposal_types = [proposal.evidence_type for proposal in proposals]
        if len(proposal_types) != len(set(proposal_types)):
            raise LLMOutputValidationError(
                "evidence request categories must be unique"
            )
        requests: list[EvidenceRequest] = []
        for proposal in proposals:
            try:
                request_contract = expected_requests[proposal.evidence_type]
            except KeyError:
                raise LLMOutputValidationError(
                    "evidence request violates role isolation"
                ) from None
            if proposal.priority is not EvidencePriority(
                request_contract["priority"]
            ):
                raise LLMOutputValidationError(
                    "evidence request priority violates role contract"
                )
            permits_trigger = bool(
                request_contract["use_dynamic_trigger_reference"]
            )
            if not permits_trigger and (
                proposal.dynamic_trigger_fact_reference is not None
            ):
                raise LLMOutputValidationError(
                    "evidence request leaked a dynamic trigger reference across roles"
                )
            if (
                proposal.dynamic_trigger_fact_reference is not None
                and proposal.dynamic_trigger_fact_reference
                != context.dynamic_trigger_fact_reference
            ):
                raise LLMOutputValidationError(
                    "evidence request cites an unknown dynamic trigger fact"
                )
            requests.append(
                EvidenceRequest.create(
                    hypothesis,
                    evidence_type=proposal.evidence_type,
                    required_fact=proposal.required_fact,
                    dynamic_trigger_fact_reference=(
                        proposal.dynamic_trigger_fact_reference
                    ),
                    priority=proposal.priority,
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
                    "reasoning provider output contains a forbidden truth field"
                )
            _reject_forbidden_fields(nested)
    elif isinstance(payload, list):
        for nested in payload:
            _reject_forbidden_fields(nested)
