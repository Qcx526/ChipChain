"""Strict response parsing and deterministic proposal materialization only."""

from chipchain.core import canonical_json_bytes
from chipchain.candidates import (
    CandidateRationaleAtom, CandidateRequirementSupport, HardwareTriggerCandidate,
    HardwareTriggerCandidateContext, validate_trigger_candidate,
)
from chipchain.trigger import (
    HardwareTriggerSpec, InstructionTriggerRequirement, RegisterAccessTriggerRequirement,
    RegisterStateTriggerRequirement, TriggerOrderRequirement,
)
from chipchain.reasoning.trigger_candidate._json import strict_json_object
from chipchain.reasoning.trigger_candidate.contracts import (
    MAX_RESPONSE_BYTES, InstructionProposal, ModelTriggerCandidateProposal,
)
from chipchain.reasoning.trigger_candidate.errors import CandidateMaterializationError, ProposalParseError


def parse_model_proposal(raw_response: str) -> ModelTriggerCandidateProposal:
    """Accept one bounded strict JSON DTO, with no repair, coercion or recovery."""

    try:
        payload = strict_json_object(raw_response, limit=MAX_RESPONSE_BYTES)
        # JSON strict mode accepts JSON arrays as tuples and enum string values,
        # but never converts strings/bools/floats into declared numeric fields.
        return ModelTriggerCandidateProposal.model_validate_json(canonical_json_bytes(payload), strict=True)
    except (ValueError, TypeError, RecursionError):
        raise ProposalParseError("model response is not a valid closed v1 JSON proposal") from None


def materialize_trigger_candidate(
    proposal: ModelTriggerCandidateProposal, context: HardwareTriggerCandidateContext,
) -> HardwareTriggerCandidate:
    """Bind only normative proposals to existing context facts, then validate.

    Sorted local proposal IDs assign local requirement slots; these slots do not
    describe source or runtime order. Only explicit order DTOs become proposed
    required-order relations. No objective facts or source identities are minted.
    """

    try:
        snapshot = HardwareTriggerCandidateContext.model_validate(context)
        dto = ModelTriggerCandidateProposal.model_validate(proposal)
        if set(dto.unresolved_condition_ids) != {c.id for c in snapshot.unresolved_conditions}:
            raise ValueError("all and only the context unresolved conditions are required")
        available = snapshot.fact_index()
        references = [ref for support in dto.supports for ref in support.evidence_refs]
        references.extend(ref for atom in dto.rationale_atoms for ref in atom.supporting_evidence_refs)
        if any(ref not in available for ref in references):
            raise ValueError("proposal reference kind/ID/owner is outside the exact context")

        requirements = (*dto.proposed_preconditions, *dto.proposed_steps)
        slots = {key: index for index, key in enumerate(sorted(r.local_id for r in requirements))}
        binding = dict(source_context_id=snapshot.source.id, architecture=snapshot.source.architecture)
        local_to_id: dict[str, str] = {}
        preconditions: list[RegisterStateTriggerRequirement] = []
        steps: list[InstructionTriggerRequirement | RegisterAccessTriggerRequirement] = []
        orders: list[TriggerOrderRequirement] = []
        for item in dto.proposed_preconditions:
            register = {"architecture": snapshot.source.architecture, **item.register_ref.model_dump()}
            state = RegisterStateTriggerRequirement.model_validate(dict(binding,
                requirement_slot=slots[item.local_id], register_ref=register,
                constraint={"kind": "exact", "value": {"width_bits": item.width_bits, "value": item.value}}))
            preconditions.append(state)
            local_to_id[item.local_id] = state.id
        for item in dto.proposed_steps:
            step: InstructionTriggerRequirement | RegisterAccessTriggerRequirement
            if isinstance(item, InstructionProposal):
                step = InstructionTriggerRequirement(**binding, requirement_slot=slots[item.local_id],
                    mnemonic=item.mnemonic, operands=None)
            else:
                register = {"architecture": snapshot.source.architecture, **item.register_ref.model_dump()}
                step = RegisterAccessTriggerRequirement.model_validate(dict(binding,
                    requirement_slot=slots[item.local_id], register_ref=register, access=item.access))
            steps.append(step)
            local_to_id[item.local_id] = step.id
        for item in dto.proposed_order:
            order = TriggerOrderRequirement.model_validate(dict(binding, kind=item.kind,
                before_id=local_to_id[item.before_id], after_id=local_to_id[item.after_id]))
            orders.append(order)
            local_to_id[item.local_id] = order.id
        spec = HardwareTriggerSpec(source=snapshot.source, preconditions=tuple(preconditions),
            steps=tuple(steps), order_requirements=tuple(orders))
        supports = tuple(CandidateRequirementSupport(requirement_id=local_to_id[s.proposal_id],
            support_kind="CONTEXT_REFERENCES", evidence_refs=s.evidence_refs, epistemic_status="HYPOTHESIZED")
            for s in dto.supports)
        atoms = tuple(CandidateRationaleAtom.model_validate(atom.model_dump()) for atom in dto.rationale_atoms)
        candidate = HardwareTriggerCandidate(context_id=snapshot.id, proposed_requirements=spec,
            evidence_bindings=supports, unresolved_condition_ids=dto.unresolved_condition_ids, rationale_atoms=atoms)
        # The frozen validator is mandatory even for ABSTAIN/empty hypotheses.
        return validate_trigger_candidate(candidate, snapshot)
    except (ValueError, TypeError, KeyError, RecursionError):
        raise CandidateMaterializationError("proposal/context or frozen candidate constraints rejected") from None
