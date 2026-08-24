"""Provider-backed adapter for the existing reasoning-agent contract."""

from __future__ import annotations

from chipchain.agents.base import (
    ReasoningAgent,
    ReasoningContext,
    _snapshot_context,
)
from chipchain.reasoning.engine import ReasoningEngine
from chipchain.reasoning.enums import ReasoningAgentType
from chipchain.reasoning.evidence_request import EvidenceRequest
from chipchain.reasoning.hypothesis import (
    AttackHypothesis,
    _canonical_reasoning_id,
)
from chipchain.reasoning.parser import ParsedReasoningContracts
from chipchain.reasoning.reasoning_result import ReasoningResult


PROVIDER_BACKED_AGENT_CONTRACT = "phase9b2c_provider_backed_agent_v1"


def provider_backed_reasoning_agent_id(
    agent_type: ReasoningAgentType | str,
) -> str:
    """Build a stable role identity without provider configuration or secrets."""

    normalized_role = ReasoningAgentType(agent_type)
    return _canonical_reasoning_id(
        "reasoning-agent",
        {
            "agent_type": normalized_role.value,
            "contract": PROVIDER_BACKED_AGENT_CONTRACT,
        },
    )


class ProviderBackedReasoningAgent(ReasoningAgent):
    """Adapt one role and one engine while invoking the provider at most once."""

    def __init__(
        self,
        context: ReasoningContext,
        *,
        role: ReasoningAgentType | str,
        engine: ReasoningEngine,
    ) -> None:
        if not isinstance(engine, ReasoningEngine):
            raise TypeError("provider-backed agent requires a ReasoningEngine")
        normalized_role = ReasoningAgentType(role)
        self._context = _snapshot_context(context)
        self._engine = engine
        self._cached_contracts: ParsedReasoningContracts | None = None
        super().__init__(
            agent_id=provider_backed_reasoning_agent_id(normalized_role),
            agent_type=normalized_role,
        )

    def produce_hypothesis(self) -> AttackHypothesis:
        """Return a detached hypothesis from the one cached provider result."""

        hypothesis, _, _ = self._contracts()
        return AttackHypothesis.model_validate(hypothesis.model_dump(mode="json"))

    def request_evidence(self) -> list[EvidenceRequest]:
        """Return detached requests from the one cached provider result."""

        _, requests, _ = self._contracts()
        return [
            EvidenceRequest.model_validate(item.model_dump(mode="json"))
            for item in requests
        ]

    def analyze(self, input_data: object) -> ReasoningResult:
        """Return the cached result after checking the supplied context identity."""

        snapshot = _snapshot_context(input_data)
        if snapshot.id != self._context.id:
            raise ValueError("agent reasoning context identity mismatch")
        _, _, result = self._contracts()
        return ReasoningResult.model_validate(result.model_dump(mode="json"))

    def _contracts(self) -> ParsedReasoningContracts:
        if self._cached_contracts is None:
            hypothesis, requests, result = self._engine.reason(
                self._context,
                role=self.agent_type,
            )
            hypothesis_snapshot = AttackHypothesis.model_validate(
                hypothesis.model_dump(mode="json")
            )
            request_snapshots = [
                EvidenceRequest.model_validate(item.model_dump(mode="json"))
                for item in requests
            ]
            result_snapshot = ReasoningResult.model_validate(
                result.model_dump(mode="json")
            )
            if hypothesis_snapshot.architecture is not self._context.architecture:
                raise ValueError("provider hypothesis architecture mismatch")
            for request in request_snapshots:
                request.validate_against(hypothesis_snapshot)
            result_snapshot.validate_against(hypothesis_snapshot)
            if not set(result_snapshot.supporting_evidence_ids).issubset(
                self._context.available_evidence_ids
            ):
                raise ValueError(
                    "provider reasoning evidence references exceed context"
                )
            self._cached_contracts = (
                hypothesis_snapshot,
                request_snapshots,
                result_snapshot,
            )
        hypothesis, requests, result = self._cached_contracts
        return (
            AttackHypothesis.model_validate(hypothesis.model_dump(mode="json")),
            [
                EvidenceRequest.model_validate(item.model_dump(mode="json"))
                for item in requests
            ],
            ReasoningResult.model_validate(result.model_dump(mode="json")),
        )
