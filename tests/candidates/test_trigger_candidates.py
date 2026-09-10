"""Benign hypothetical proposals; support consistency is never verification."""

import pytest
from pydantic import ValidationError

from chipchain.candidates import (
    CandidateRationaleAtom, CandidateRequirementSupport, HardwareTriggerCandidate,
    ObjectiveFactKind as K, ObjectiveFactReference, validate_trigger_candidate,
)
from chipchain.trigger import HardwareTriggerSpec, InstructionTriggerRequirement, TriggerOrderRequirement


def proposal(context, *, refs=None, unsupported=False, spec=None):
    if spec is None:
        step = InstructionTriggerRequirement(source_context_id=context.source.id,
            architecture=context.source.architecture, requirement_slot=0, mnemonic="synthetic.op")
        spec = HardwareTriggerSpec(source=context.source, steps=(step,))
    if refs is None:
        refs = (next(r for r in context.fact_index() if r.kind == K.ISA_OBSERVATION),)
    supports = tuple(CandidateRequirementSupport(requirement_id=r.id,
        support_kind="NO_SUPPORT" if unsupported else "CONTEXT_REFERENCES",
        evidence_refs=() if unsupported else refs,
        epistemic_status="UNSUPPORTED" if unsupported else "HYPOTHESIZED")
        for r in (*spec.preconditions, *spec.steps, *spec.order_requirements))
    return HardwareTriggerCandidate(context_id=context.id, proposed_requirements=spec,
        evidence_bindings=supports, unresolved_condition_ids=tuple(c.id for c in context.unresolved_conditions))


def test_hypothesized_requirement_does_not_upgrade_observation(context):
    original = context.model_dump_json()
    candidate = proposal(context)
    validated = validate_trigger_candidate(candidate, context)
    assert validated.status == "HYPOTHESIS"
    assert validated.evidence_bindings[0].epistemic_status == "HYPOTHESIZED"
    assert validated is not candidate
    assert HardwareTriggerCandidate.model_validate_json(candidate.model_dump_json()).id == candidate.id
    assert original == context.model_dump_json()
    assert not hasattr(validated, "verified") and not hasattr(validated, "score")


@pytest.mark.parametrize("kind", list(K))
def test_each_available_reference_kind_resolves(context_inputs, hardware_case, kind):
    from chipchain.candidates import build_trigger_candidate_context
    context = build_trigger_candidate_context(**context_inputs, behavior_fragment=hardware_case.fragment(context_inputs["raw_si"]))
    refs = tuple(r for r in context.fact_index() if r.kind == kind)
    assert refs
    assert validate_trigger_candidate(proposal(context, refs=refs), context).status == "HYPOTHESIS"


@pytest.mark.parametrize("mutation", [{"fact_id": "does-not-exist"}, {"kind": "RTL_OBSERVATION"}, {"owner_id": "another-artifact"}])
def test_reference_kind_identity_source_fail_closed(context, mutation):
    ref = next(r for r in context.fact_index() if r.kind == K.ISA_OBSERVATION)
    bad = ObjectiveFactReference.model_validate(dict(ref.model_dump(mode="json"), **mutation))
    with pytest.raises(ValueError, match="reference"):
        validate_trigger_candidate(proposal(context, refs=(bad,)), context)


def test_comparison_reference_cannot_cross_scope(context):
    ref = next(r for r in context.fact_index() if r.kind == K.FIELD_COMPARISON)
    other = ref.model_copy(update={"owner_id": "another-scope-pair"})
    with pytest.raises(ValueError, match="reference"):
        validate_trigger_candidate(proposal(context, refs=(other,)), context)


@pytest.mark.parametrize("status", ["OBSERVED", "CORRELATED", "VERIFIED", "BYTE_VERIFIED", "SATISFIED"])
def test_proposal_status_never_becomes_evidence_status(context, status):
    support = proposal(context).evidence_bindings[0].model_dump(mode="json")
    support["epistemic_status"] = status
    with pytest.raises(ValidationError):
        CandidateRequirementSupport.model_validate(support)


def test_unsupported_has_no_implicit_evidence(context):
    candidate = proposal(context, unsupported=True)
    assert validate_trigger_candidate(candidate, context).evidence_bindings[0].evidence_refs == ()
    support = proposal(context).evidence_bindings[0].model_dump(mode="json")
    support["evidence_refs"] = []
    with pytest.raises(ValueError):
        CandidateRequirementSupport.model_validate(support)
    support = candidate.evidence_bindings[0].model_dump(mode="json")
    support["evidence_refs"] = [next(iter(context.fact_index())).model_dump(mode="json")]
    with pytest.raises(ValueError):
        CandidateRequirementSupport.model_validate(support)


@pytest.mark.parametrize("mutation", ["duplicate_support", "duplicate_reference", "wrong_requirement", "absent_support", "wrong_context",
    "wrong_source", "wrong_architecture", "drop_unresolved", "unknown_unresolved", "duplicate_unresolved"])
def test_candidate_closed_binding(context, mutation):
    candidate = proposal(context)
    data = candidate.model_dump(mode="json")
    if mutation == "duplicate_support": data["evidence_bindings"].append(data["evidence_bindings"][0])
    elif mutation == "duplicate_reference": data["evidence_bindings"][0]["evidence_refs"] *= 2
    elif mutation == "wrong_requirement": data["evidence_bindings"][0]["requirement_id"] = "outside-spec"
    elif mutation == "absent_support": data["evidence_bindings"] = []
    elif mutation == "wrong_context": data["context_id"] = "another-context"
    elif mutation == "wrong_source": data["proposed_requirements"]["source"]["artifact"]["artifact_id"] = "another-source"
    elif mutation == "wrong_architecture": data["proposed_requirements"]["steps"][0]["architecture"] = "arm"
    elif mutation == "drop_unresolved": data["unresolved_condition_ids"].pop()
    elif mutation == "unknown_unresolved": data["unresolved_condition_ids"].append("unrelated-condition")
    else: data["unresolved_condition_ids"].append(data["unresolved_condition_ids"][0])
    with pytest.raises(ValueError):
        validate_trigger_candidate(HardwareTriggerCandidate.model_validate(data), context)


def test_detached_validation_of_unchecked_instances(context):
    candidate = proposal(context)
    broken = candidate.model_copy(update={"status": "VERIFIED"})
    with pytest.raises(ValueError):
        validate_trigger_candidate(broken, context)
    broken_context = context.model_copy(update={"unresolved_conditions": ()})
    with pytest.raises(ValueError):
        validate_trigger_candidate(candidate, broken_context)


def ordered_spec(context):
    binding = dict(source_context_id=context.source.id, architecture=context.source.architecture)
    steps = tuple(InstructionTriggerRequirement(**binding, requirement_slot=i, mnemonic="synthetic.op") for i in range(2))
    edge = TriggerOrderRequirement(**binding, kind="required_precedes", before_id=steps[0].id, after_id=steps[1].id)
    return HardwareTriggerSpec(source=context.source, steps=steps, order_requirements=(edge,))


def test_proposed_order_reuses_v2_4_not_runtime_order(context):
    spec = ordered_spec(context)
    candidate = validate_trigger_candidate(proposal(context, spec=spec), context)
    assert len(candidate.evidence_bindings) == 3
    assert all(s.epistemic_status == "HYPOTHESIZED" for s in candidate.evidence_bindings)
    assert "runtime_precedes" not in candidate.model_dump_json()


@pytest.mark.parametrize("mutation", ["missing_endpoint", "cycle", "duplicate_slot", "duplicate_step"])
def test_frozen_order_and_slot_integrity_preserved(context, mutation):
    data = ordered_spec(context).model_dump(mode="json")
    if mutation == "missing_endpoint": data["order_requirements"][0]["before_id"] = "absent-step"
    elif mutation == "cycle":
        edge = dict(data["order_requirements"][0])
        edge["before_id"], edge["after_id"] = edge["after_id"], edge["before_id"]
        data["order_requirements"].append(edge)
    elif mutation == "duplicate_slot":
        data["steps"][1]["requirement_slot"] = data["steps"][0]["requirement_slot"]
        data["steps"][1]["mnemonic"] = "another.synthetic"
    else: data["steps"].append(data["steps"][0])
    with pytest.raises(ValueError):
        HardwareTriggerSpec.model_validate(data)


def rationale(context, text="A synthetic observation motivates this hypothesis."):
    return CandidateRationaleAtom(statement_id="synthetic-statement", text=text,
        supporting_evidence_refs=(next(iter(context.fact_index())),))


def test_rationale_changes_candidate_not_objective_identity(context):
    candidate = proposal(context)
    context_id = context.id
    with_text = HardwareTriggerCandidate.model_validate(dict(candidate.model_dump(), rationale_atoms=(rationale(context),)))
    assert validate_trigger_candidate(with_text, context).id != candidate.id
    assert context.id == context_id
    assert with_text.proposed_requirements.id == candidate.proposed_requirements.id
    assert CandidateRationaleAtom.model_validate_json(rationale(context).model_dump_json()).id == rationale(context).id
    assert rationale(context, "Hypothesis: a benign synthetic proposal.").status == "HYPOTHESIS"


@pytest.mark.parametrize("text", ["", " " * 5, "x" * 241, "bad\nline", "bad\tline", "bad\x00line", "/tmp/file", "~/file",
    "C:\\Users\\file", "file:/tmp/file", "\\\\server\\share", "core 0: 0x12345678", "DELAYED r1=0000000000000000",
    "pc,instr,gpr,csr,binary,mode,instr_str", "0" * 16 + " " + "1" * 16])
def test_rationale_no_paths_control_or_log_channel(context, text):
    with pytest.raises(ValueError):
        rationale(context, text)


def test_rationale_cannot_mint_fact_or_evidence_level(context):
    data = rationale(context).model_dump(mode="json")
    for key, value in (("evidence_level", "BYTE_VERIFIED"), ("status", "VERIFIED"), ("new_evidence_id", "made-up")):
        with pytest.raises(ValueError):
            CandidateRationaleAtom.model_validate(dict(data, **{key: value}))
    data["supporting_evidence_refs"][0]["fact_id"] = "invented-by-rationale"
    candidate = proposal(context)
    candidate = HardwareTriggerCandidate.model_validate(dict(candidate.model_dump(), rationale_atoms=(data,)))
    with pytest.raises(ValueError, match="reference"):
        validate_trigger_candidate(candidate, context)


@pytest.mark.parametrize("field", ["verified", "verification_status", "vulnerability", "cause", "causal", "root_cause", "bug_trigger",
    "critical_instruction", "exploit", "verified_vulnerability", "necessary", "sufficient", "confidence", "score"])
def test_no_scientific_verdict_fields(context, field):
    candidate = proposal(context)
    with pytest.raises(ValueError):
        HardwareTriggerCandidate.model_validate(dict(candidate.model_dump(), **{field: True}))
    assert field not in HardwareTriggerCandidate.model_fields
    assert field not in type(context).model_fields
