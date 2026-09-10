"""Hypothesis-only proposals reusing the frozen normative Trigger IR."""

import re
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from chipchain.core import Identifier
from chipchain.trigger import HardwareTriggerSpec
from chipchain.candidates.base import CandidateModel
from chipchain.candidates.enums import CandidateEpistemicStatus as E, CandidateStatus as S, CandidateSupportKind as K
from chipchain.candidates.facts import ObjectiveFactReference


class CandidateRequirementSupport(CandidateModel):
    """References motivate a proposal; they do not satisfy a requirement."""

    _namespace = "v2-candidate-requirement-support-v1"
    requirement_id: Identifier
    support_kind: K
    evidence_refs: Annotated[tuple[ObjectiveFactReference, ...], Field(max_length=128)] = ()
    epistemic_status: Literal[E.HYPOTHESIZED, E.UNSUPPORTED]

    @field_validator("evidence_refs")
    @classmethod
    def canonical_refs(cls, refs: tuple[ObjectiveFactReference, ...]) -> tuple[ObjectiveFactReference, ...]:
        if len(refs) != len(set(refs)):
            raise ValueError("duplicate evidence reference")
        return tuple(sorted(refs, key=lambda ref: ref.id))

    @model_validator(mode="after")
    def validate_support(self) -> Self:
        if self.epistemic_status == E.UNSUPPORTED:
            if self.support_kind != K.NO_SUPPORT or self.evidence_refs:
                raise ValueError("UNSUPPORTED explicitly has no supporting references")
        elif self.support_kind != K.CONTEXT_REFERENCES or not self.evidence_refs:
            raise ValueError("hypothesized requirement needs context references")
        return self


class CandidateRationaleAtom(CandidateModel):
    """Bounded model reasoning, not an evidence level or objective fact."""

    _namespace = "v2-candidate-rationale-atom-v1"
    statement_id: Identifier
    text: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    supporting_evidence_refs: Annotated[tuple[ObjectiveFactReference, ...], Field(min_length=1, max_length=32)]
    status: Literal[S.HYPOTHESIS] = S.HYPOTHESIS

    @field_validator("text")
    @classmethod
    def safe_reasoning_text(cls, text: str) -> str:
        # Deliberately narrow prose, not a general text/document transport.
        if not text.strip() or any(ord(c) < 32 or ord(c) > 126 for c in text):
            raise ValueError("rationale requires bounded printable ASCII prose")
        if any(c in text for c in "/\\~") or re.search(r"(?i)(file:|(?:^|\s)[a-z]:|core\s+\d+|DELAYED|HartID|pc,instr|0x[0-9a-f]{8,})", text):
            raise ValueError("paths and raw log fragments are forbidden in rationale")
        if text.count(",") > 4 or len(re.findall(r"\b[0-9a-fA-F]{8,}\b", text)) > 1:
            raise ValueError("rationale is not a raw payload channel")
        return text

    @field_validator("supporting_evidence_refs")
    @classmethod
    def canonical_refs(cls, refs: tuple[ObjectiveFactReference, ...]) -> tuple[ObjectiveFactReference, ...]:
        if len(refs) != len(set(refs)):
            raise ValueError("duplicate rationale reference")
        return tuple(sorted(refs, key=lambda ref: ref.id))


class HardwareTriggerCandidate(CandidateModel):
    """Proposed V2-4 requirements, never verified/satisfied/causal conclusions."""

    _namespace = "v2-hardware-trigger-candidate-v1"
    contract: Literal["v2_hardware_trigger_candidate_v1"] = "v2_hardware_trigger_candidate_v1"
    status: Literal[S.HYPOTHESIS] = S.HYPOTHESIS
    context_id: Identifier
    proposed_requirements: HardwareTriggerSpec
    evidence_bindings: Annotated[tuple[CandidateRequirementSupport, ...], Field(max_length=256)]
    unresolved_condition_ids: Annotated[tuple[Identifier, ...], Field(max_length=80)]
    rationale_atoms: Annotated[tuple[CandidateRationaleAtom, ...], Field(max_length=32)] = ()

    @field_validator("evidence_bindings", "rationale_atoms")
    @classmethod
    def canonical_models(cls, items: tuple) -> tuple:
        if len({i.id for i in items}) != len(items):
            raise ValueError("duplicate candidate member ID")
        return tuple(sorted(items, key=lambda i: i.id))

    @field_validator("unresolved_condition_ids")
    @classmethod
    def canonical_ids(cls, ids: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate unresolved condition ID")
        return tuple(sorted(ids))

    @model_validator(mode="after")
    def validate_requirement_bindings(self) -> Self:
        requirements = self.proposed_requirements
        expected = {r.id for r in (*requirements.preconditions, *requirements.steps, *requirements.order_requirements)}
        actual = [b.requirement_id for b in self.evidence_bindings]
        if len(actual) != len(set(actual)) or set(actual) != expected:
            raise ValueError("exactly one support binding required for every proposed requirement/order")
        if len({a.statement_id for a in self.rationale_atoms}) != len(self.rationale_atoms):
            raise ValueError("duplicate rationale statement ID")
        return self
