"""Malformed/adversarial JSON rejection and frozen proposal materialization."""

import json

import pytest

from chipchain.reasoning.trigger_candidate import (
    CandidateMaterializationError, ModelTriggerCandidateProposal, ProposalParseError,
    materialize_trigger_candidate, parse_model_proposal,
)


def test_valid_dto_maps_four_supported_requirement_kinds(context, proposal_payload):
    dto = parse_model_proposal(json.dumps(proposal_payload))
    candidate = materialize_trigger_candidate(dto, context)
    spec = candidate.proposed_requirements
    assert candidate.status == "HYPOTHESIS"
    assert {s.epistemic_status for s in candidate.evidence_bindings} == {"HYPOTHESIZED"}
    assert {r.kind for r in (*spec.preconditions, *spec.steps)} == {"register_state", "register_access", "instruction"}
    assert len(spec.order_requirements) == 1 and spec.order_requirements[0].kind == "required_precedes"
    assert {r.requirement_slot for r in (*spec.preconditions, *spec.steps)} == {0, 1, 2}
    assert all(r.source_context_id == context.source.id and r.architecture == context.source.architecture for r in (*spec.preconditions, *spec.steps))
    instruction = next(s for s in spec.steps if s.kind == "instruction")
    assert instruction.operands is None  # Explicitly unconstrained, not decoded operands.
    assert spec.preconditions[0].constraint.value.value == "0x2"
    assert spec.preconditions[0].register_ref.architecture == context.source.architecture
    assert all(r.id.startswith("v2-trigger-") for r in (*spec.preconditions, *spec.steps, *spec.order_requirements))
    assert ModelTriggerCandidateProposal.model_validate_json(dto.model_dump_json()).id == dto.id


@pytest.mark.parametrize("raw", ["", "not-json", "{}{}", "[]", "null", "true", "```json\n{}\n```", "prose {}", "{} trailing",
    '{"a":1,"a":2}', '{"a":{"b":1,"b":1}}', '{"a":NaN}', '{"a":Infinity}', '{"a":-Infinity}', '{"a":1e999}',
    '{"a":1.0}', '\ufeff{}', '{"a":"\ud800"}', '{"a":"\\ud800"}', '{"a":' + '[' * 40 + '0' + ']' * 40 + '}',
    '{"a":' + '[' * 1500 + '0' + ']' * 1500 + '}', " " * 65537])
def test_invalid_json_rejected_without_repair(raw):
    with pytest.raises(ProposalParseError):
        parse_model_proposal(raw)


@pytest.mark.parametrize("mutation", ["top_level", "escaped_key", "nested"])
def test_duplicate_keys_in_otherwise_valid_proposals_are_rejected(proposal_payload, abstain_payload, mutation):
    if mutation == "nested":
        raw = json.dumps(proposal_payload).replace('"width_bits": 8', '"width_bits": 8, "width_bits": 8', 1)
    else:
        raw = json.dumps(abstain_payload)
        key = '"disposition"' if mutation == "top_level" else '"dispositi\\u006fn"'
        raw = raw[:-1] + ',' + key + ':"ABSTAIN"}'
    # A last-key-wins JSON loader would produce a fully valid DTO here.
    ModelTriggerCandidateProposal.model_validate_json(json.dumps(json.loads(raw)), strict=True)
    with pytest.raises(ProposalParseError):
        parse_model_proposal(raw)


@pytest.mark.parametrize("access", ["read", "write", "read_write"])
def test_supported_access_and_immediate_order_are_preserved(context, proposal_payload, access):
    proposal_payload["proposed_steps"][1]["access"] = access
    proposal_payload["proposed_order"][0]["kind"] = "required_immediately_precedes"
    candidate = materialize_trigger_candidate(parse_model_proposal(json.dumps(proposal_payload)), context)
    assert next(s for s in candidate.proposed_requirements.steps if s.kind == "register_access").access == access
    assert candidate.proposed_requirements.order_requirements[0].kind == "required_immediately_precedes"


@pytest.mark.parametrize("field", ["schema_version", "disposition", "proposed_preconditions", "proposed_steps", "proposed_order", "supports", "rationale_atoms", "unresolved_condition_ids"])
def test_every_top_level_field_is_required(abstain_payload, field):
    del abstain_payload[field]
    with pytest.raises(ProposalParseError):
        parse_model_proposal(json.dumps(abstain_payload))


@pytest.mark.parametrize("mutation", ["unknown_kind", "memory_kind", "masked_constraint", "architecture", "source", "operands", "unknown_register_class",
    "unknown_access", "numeric_string", "float_width", "bool_width", "zero_width", "overflow", "numeric_value", "unconstrained_value",
    "wrong_enum", "extra_ref", "path_ref", "missing_ref_owner", "duplicate_step", "cross_category_id", "missing_support", "duplicate_support",
    "wrong_support", "empty_refs", "duplicate_refs", "duplicate_unresolved", "missing_order_endpoint", "order_to_precondition"])
def test_schema_type_and_reference_shape_fail_closed(proposal_payload, mutation):
    pre = proposal_payload["proposed_preconditions"][0]
    step = proposal_payload["proposed_steps"][0]
    support = proposal_payload["supports"][0]
    if mutation == "unknown_kind": step["kind"] = "unknown"
    elif mutation == "memory_kind": step["kind"] = "memory_access"
    elif mutation == "masked_constraint": pre["mask"] = "0xff"
    elif mutation == "architecture": step["architecture"] = "arm"
    elif mutation == "source": proposal_payload["source_context_id"] = "arbitrary-source"
    elif mutation == "operands": step["operands"] = []
    elif mutation == "unknown_register_class": pre["register_ref"]["register_class"] = "vector"
    elif mutation == "unknown_access": proposal_payload["proposed_steps"][1]["access"] = "execute"
    elif mutation == "numeric_string": pre["width_bits"] = "8"
    elif mutation == "float_width": pre["width_bits"] = 8.0
    elif mutation == "bool_width": pre["width_bits"] = True
    elif mutation == "zero_width": pre["width_bits"] = 0
    elif mutation == "overflow": pre["value"] = "0x100"
    elif mutation == "numeric_value": pre["value"] = 2
    elif mutation == "unconstrained_value": pre["value"] = None
    elif mutation == "wrong_enum": proposal_payload["disposition"] = "VERIFIED"
    elif mutation == "extra_ref": support["evidence_refs"][0]["text"] = "Invented evidence."
    elif mutation == "path_ref": support["evidence_refs"][0]["fact_id"] = "/tmp/fact"
    elif mutation == "missing_ref_owner": del support["evidence_refs"][0]["owner_id"]
    elif mutation == "duplicate_step": proposal_payload["proposed_steps"].append(step)
    elif mutation == "cross_category_id": pre["local_id"] = step["local_id"]
    elif mutation == "missing_support": proposal_payload["supports"].pop()
    elif mutation == "duplicate_support": proposal_payload["supports"].append(support)
    elif mutation == "wrong_support": support["proposal_id"] = "missing-proposal"
    elif mutation == "empty_refs": support["evidence_refs"] = []
    elif mutation == "duplicate_refs": support["evidence_refs"] *= 2
    elif mutation == "duplicate_unresolved": proposal_payload["unresolved_condition_ids"] *= 2
    elif mutation == "missing_order_endpoint": proposal_payload["proposed_order"][0]["after_id"] = "missing-step"
    else: proposal_payload["proposed_order"][0]["after_id"] = pre["local_id"]
    with pytest.raises(ProposalParseError):
        parse_model_proposal(json.dumps(proposal_payload))


@pytest.mark.parametrize("change", [{"fact_id": "invented-fact"}, {"owner_id": "different-source"}, {"kind": "RTL_OBSERVATION"}])
def test_typed_reference_resolution_against_exact_context(context, proposal_payload, change):
    proposal_payload["supports"][0]["evidence_refs"][0].update(change)
    dto = parse_model_proposal(json.dumps(proposal_payload))
    with pytest.raises(CandidateMaterializationError):
        materialize_trigger_candidate(dto, context)


@pytest.mark.parametrize("mutation", ["drop", "invent", "rationale_ref", "cycle", "self_loop"])
def test_materialization_rejects_unresolved_and_order_violations(context, proposal_payload, mutation):
    if mutation == "drop": proposal_payload["unresolved_condition_ids"].pop()
    elif mutation == "invent": proposal_payload["unresolved_condition_ids"].append("invented-condition")
    elif mutation == "rationale_ref": proposal_payload["rationale_atoms"][0]["supporting_evidence_refs"][0] = {
        "kind": "ALIGNED_PAIR", "fact_id": "another-pair", "owner_id": "another-alignment"}
    elif mutation == "self_loop": proposal_payload["proposed_order"][0]["after_id"] = "step-a"
    else:
        proposal_payload["proposed_order"].append({"local_id": "order-b", "kind": "required_precedes", "before_id": "step-b", "after_id": "step-a"})
        proposal_payload["supports"].append({"proposal_id": "order-b", "evidence_refs": proposal_payload["supports"][0]["evidence_refs"]})
    with pytest.raises(CandidateMaterializationError):
        materialize_trigger_candidate(parse_model_proposal(json.dumps(proposal_payload)), context)


@pytest.mark.parametrize("field", ["verified", "vulnerability", "causal", "root_cause", "necessary", "sufficient", "confidence", "score", "evidence_level", "epistemic_status"])
def test_no_verdict_or_epistemic_authority_from_model(proposal_payload, field):
    proposal_payload[field] = True
    with pytest.raises(ProposalParseError):
        parse_model_proposal(json.dumps(proposal_payload))


@pytest.mark.parametrize("target", ["proposed_steps", "supports", "rationale_atoms"])
def test_nested_claim_escalation_rejected(proposal_payload, target):
    proposal_payload[target][0]["epistemic_status"] = "OBSERVED"
    with pytest.raises(ProposalParseError):
        parse_model_proposal(json.dumps(proposal_payload))


@pytest.mark.parametrize("text", ["file:/tmp/source", "C:\\Users\\file", "text\nlog", "x" * 241, "DELAYED r1=0000000000000000", "0x" + "a" * 200])
def test_frozen_rationale_constraints_are_reused(proposal_payload, text):
    proposal_payload["rationale_atoms"][0]["text"] = text
    with pytest.raises(ProposalParseError):
        parse_model_proposal(json.dumps(proposal_payload))


def test_abstain_preserves_all_unresolved_conditions(context, abstain_payload):
    candidate = materialize_trigger_candidate(parse_model_proposal(json.dumps(abstain_payload)), context)
    assert candidate.status == "HYPOTHESIS"
    assert not candidate.proposed_requirements.steps and not candidate.proposed_requirements.preconditions
    assert not candidate.evidence_bindings
    assert set(candidate.unresolved_condition_ids) == {c.id for c in context.unresolved_conditions}


def test_abstain_can_have_bounded_referenced_rationale(context, abstain_payload, proposal_payload):
    abstain_payload["rationale_atoms"] = proposal_payload["rationale_atoms"]
    abstain_payload["rationale_atoms"][0]["text"] = "Insufficient evidence for a supported trigger hypothesis."
    candidate = materialize_trigger_candidate(parse_model_proposal(json.dumps(abstain_payload)), context)
    assert len(candidate.rationale_atoms) == 1 and not candidate.proposed_requirements.steps


def test_abstention_cannot_hide_requirements(proposal_payload, abstain_payload):
    proposal_payload["disposition"] = "ABSTAIN"
    abstain_payload["disposition"] = "PROPOSE"
    for payload in (proposal_payload, abstain_payload):
        with pytest.raises(ProposalParseError):
            parse_model_proposal(json.dumps(payload))


def test_proposal_collection_order_does_not_create_order_or_change_candidate(context, proposal_payload):
    first = materialize_trigger_candidate(parse_model_proposal(json.dumps(proposal_payload)), context)
    for key in ("proposed_preconditions", "proposed_steps", "proposed_order", "supports", "rationale_atoms", "unresolved_condition_ids"):
        proposal_payload[key].reverse()
    second = materialize_trigger_candidate(parse_model_proposal(json.dumps(proposal_payload)), context)
    assert first.id == second.id
    proposal_payload["proposed_order"] = []
    proposal_payload["supports"] = [s for s in proposal_payload["supports"] if s["proposal_id"] != "order-a"]
    unordered = materialize_trigger_candidate(parse_model_proposal(json.dumps(proposal_payload)), context)
    assert not unordered.proposed_requirements.order_requirements


def test_materializer_detached_revalidation(context, proposal_payload):
    dto = parse_model_proposal(json.dumps(proposal_payload))
    unchecked = dto.model_copy(update={"disposition": "VERIFIED"})
    with pytest.raises(CandidateMaterializationError):
        materialize_trigger_candidate(unchecked, context)
    with pytest.raises(CandidateMaterializationError):
        materialize_trigger_candidate(dto, context.model_copy(update={"si_sha256": "0" * 64}))
