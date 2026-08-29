"""Private transient recorders for the Phase 10D execution harness."""

from __future__ import annotations

from dataclasses import dataclass, field

from chipchain.evaluation.ablation import PromptVisibilityAuditor
from chipchain.evaluation.ablation_models import (
    PromptVisibilityAudit,
    prompt_visibility_audit_id,
)
from chipchain.evaluation.enums import PromptVisibilityAuditStatus
from chipchain.evaluation.experiment_models import (
    structured_prompt_request_sha256,
)
from chipchain.evaluation.public_knowledge_readiness import (
    PublicKnowledgeLeakageAuditor,
)
from chipchain.evaluation.public_knowledge_readiness_models import (
    PublicKnowledgeLeakageAudit,
    PublicKnowledgeLeakageAuditStatus,
)
from chipchain.reasoning.enums import (
    ReasoningAgentType,
    ReasoningPromptVisibility,
)
from chipchain.reasoning.knowledge_projection import KnowledgeContentProjection
from chipchain.reasoning.models import StructuredPromptRequest
from chipchain.reasoning.parser import ConstrainedReasoningOutputParser
from chipchain.reasoning.prompts import RoleBasedReasoningPromptBuilder
from chipchain.reasoning.provider import ReasoningProvider


class _PromptVisibilityLeakError(RuntimeError):
    """Private control-flow error for a masked pre-transport audit failure."""


class _PublicKnowledgePromptGateError(RuntimeError):
    """Private error for projected hash or structured-leakage mismatch."""


@dataclass
class _InvocationAttempt:
    role: ReasoningAgentType
    prompt: StructuredPromptRequest | None = None
    raw_response: str | None = None
    prompt_entered: bool = False
    provider_entered: bool = False
    parse_entered: bool = False
    parse_completed: bool = False
    error: Exception | None = None
    audit: PromptVisibilityAudit | None = None
    public_knowledge_audit: PublicKnowledgeLeakageAudit | None = None


@dataclass
class _PerCaseInvocationTrace:
    attempts: dict[ReasoningAgentType, _InvocationAttempt] = field(
        default_factory=dict
    )

    def attempt(self, role: ReasoningAgentType | str) -> _InvocationAttempt:
        normalized = ReasoningAgentType(role)
        return self.attempts.setdefault(
            normalized, _InvocationAttempt(role=normalized)
        )


class _RecordingPromptBuilder:
    """Delegate exact prompt construction and audit MASKED before transport."""

    def __init__(
        self,
        delegate: RoleBasedReasoningPromptBuilder,
        trace: _PerCaseInvocationTrace,
        *,
        masked_hidden_reference_ids: list[str] | None,
        knowledge_projection: KnowledgeContentProjection | None = None,
        expected_prompt_sha256_by_role: dict[ReasoningAgentType, str]
        | None = None,
        expected_leakage_audit_id_by_role: dict[ReasoningAgentType, str]
        | None = None,
        expected_visibility_audit_id_by_role: dict[ReasoningAgentType, str]
        | None = None,
    ) -> None:
        self._delegate = delegate
        self._trace = trace
        self._hidden = masked_hidden_reference_ids
        self._projection = knowledge_projection
        self._expected_hashes = expected_prompt_sha256_by_role
        self._expected_leakage_audits = expected_leakage_audit_id_by_role
        self._expected_visibility_audits = expected_visibility_audit_id_by_role
        attachments = (
            self._projection,
            self._expected_hashes,
            self._expected_leakage_audits,
        )
        if any(item is not None for item in attachments) and not all(
            item is not None for item in attachments
        ):
            raise ValueError("public prompt gate requires complete attachment")

    def build(
        self,
        context,
        *,
        role: ReasoningAgentType | str,
        visibility: ReasoningPromptVisibility | str,
    ) -> StructuredPromptRequest:
        attempt = self._trace.attempt(role)
        attempt.prompt_entered = True
        try:
            if self._projection is None:
                prompt = self._delegate.build(
                    context, role=role, visibility=visibility
                )
            else:
                prompt = self._delegate.build_with_knowledge_projection(
                    context,
                    role=role,
                    visibility=visibility,
                    knowledge_projection=self._projection,
                )
            attempt.prompt = prompt
            if self._projection is not None:
                normalized_role = ReasoningAgentType(role)
                leakage = PublicKnowledgeLeakageAuditor.audit(
                    prompt,
                    forbidden_exact_values=[],
                )
                attempt.public_knowledge_audit = leakage
                if (
                    leakage.status
                    is not PublicKnowledgeLeakageAuditStatus.PASS
                    or leakage.id
                    != self._expected_leakage_audits[normalized_role]
                    or structured_prompt_request_sha256(prompt)
                    != self._expected_hashes[normalized_role]
                ):
                    raise _PublicKnowledgePromptGateError(
                        "public projected prompt provenance gate failed"
                    )
            if self._hidden is not None:
                audit = self._audit_masked_prompt(prompt)
                attempt.audit = audit
                if audit.status is PromptVisibilityAuditStatus.LEAK_DETECTED:
                    raise _PromptVisibilityLeakError(
                        "masked prompt visibility audit failed"
                    )
                if (
                    self._projection is not None
                    and self._expected_visibility_audits is not None
                    and audit.id
                    != self._expected_visibility_audits[
                        ReasoningAgentType(role)
                    ]
                ):
                    raise _PublicKnowledgePromptGateError(
                        "public projected MASKED audit provenance failed"
                    )
            return prompt
        except Exception as error:
            attempt.error = error
            raise

    def _audit_masked_prompt(
        self, prompt: StructuredPromptRequest
    ) -> PromptVisibilityAudit:
        if self._hidden:
            return PromptVisibilityAuditor.audit(
                prompt,
                hidden_reference_ids=self._hidden,
                metadata={"phase10d_step2": True},
            )
        prompt_hash = structured_prompt_request_sha256(prompt)
        return PromptVisibilityAudit(
            id=prompt_visibility_audit_id(
                prompt_sha256=prompt_hash,
                hidden_reference_ids=[],
                leaked_reference_ids=[],
                status=PromptVisibilityAuditStatus.PASS,
            ),
            prompt_sha256=prompt_hash,
            hidden_reference_ids=[],
            leaked_reference_ids=[],
            status=PromptVisibilityAuditStatus.PASS,
            metadata={"phase10d_step2": True},
        )


class _RecordingReasoningProvider(ReasoningProvider):
    """Delegate exactly one provider call and retain its text transiently."""

    def __init__(
        self, delegate: ReasoningProvider, trace: _PerCaseInvocationTrace
    ) -> None:
        self._delegate = delegate
        self._trace = trace

    def generate(self, request: StructuredPromptRequest) -> str:
        role = ReasoningAgentType(request.role)
        attempt = self._trace.attempt(role)
        attempt.provider_entered = True
        try:
            raw = self._delegate.generate(request)
            if isinstance(raw, str):
                attempt.raw_response = raw
            return raw
        except Exception as error:
            attempt.error = error
            raise


class _RecordingReasoningParser:
    """Delegate constrained parsing and record only bounded stage state."""

    def __init__(
        self,
        delegate: ConstrainedReasoningOutputParser,
        trace: _PerCaseInvocationTrace,
    ) -> None:
        self._delegate = delegate
        self._trace = trace

    def parse(self, raw_output, *, context, role):
        attempt = self._trace.attempt(role)
        attempt.parse_entered = True
        try:
            result = self._delegate.parse(
                raw_output, context=context, role=role
            )
            attempt.parse_completed = True
            return result
        except Exception as error:
            attempt.error = error
            raise
