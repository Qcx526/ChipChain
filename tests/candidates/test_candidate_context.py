"""Synthetic-only compact context integrity; no real testcase data."""

import json

import pytest
from pydantic import ValidationError

from chipchain.anchors import parse_hardware_test_elf
from chipchain.candidates import (
    HardwareTriggerCandidateContext, ObjectiveFactKind as K, UnresolvedCondition,
    UnresolvedConditionKind as U, build_trigger_candidate_context, candidate_context_view,
    serialize_candidate_context,
)
from chipchain.evidence import AlignmentScope, ComparableField, DivergenceObservation, align_common_program


def test_context_determinism_roundtrip_and_compact_view(context, context_inputs):
    again = build_trigger_candidate_context(**context_inputs)
    assert again == context and again.id == context.id
    assert HardwareTriggerCandidateContext.model_validate_json(context.model_dump_json()) == context
    assert serialize_candidate_context(again) == serialize_candidate_context(context)
    assert json.loads(serialize_candidate_context(context)) == candidate_context_view(context)
    assert len(serialize_candidate_context(context)) < 30000
    assert context.context_records[1].alignment_ordinal == 1
    assert len(context.fact_index()) == len(set(context.fact_index()))
    data = context.model_dump_json()
    for forbidden in ("raw_line", "operand_tokens", "data_records", "load_segments", "signature", "runtime_precedes"):
        assert forbidden not in data


@pytest.mark.parametrize("before,after,ordinals", [(0, 0, [1]), (8, 8, [0, 1, 2]), (1, 0, [0, 1]), (0, 1, [1, 2])])
def test_bounded_window(context_inputs, before, after, ordinals):
    context = build_trigger_candidate_context(**dict(context_inputs, before=before, after=after))
    assert [p.alignment_ordinal for p in context.context_records] == ordinals


@pytest.mark.parametrize("bad", [-1, 9, True, 1.0, "1", None])
@pytest.mark.parametrize("field", ["before", "after"])
def test_bad_bound_fails_before_any_anchor(context_inputs, monkeypatch, field, bad):
    def forbidden(*a, **kw):
        pytest.fail("invalid bound must fail before source processing")
    monkeypatch.setattr("chipchain.candidates.context.revalidate_hardware_test_elf", forbidden)
    with pytest.raises(ValueError, match="bounds"):
        build_trigger_candidate_context(**dict(context_inputs, **{field: bad}))


def test_missing_anchor_never_propagates_label(context):
    middle = context.context_records[1]
    trace_ids = {a.observation_id for a in context.trace_anchors}
    assert {middle.isa.observation_id, middle.rtl.observation_id} <= trace_ids
    missing = [c for c in context.unresolved_conditions if c.kind == U.NO_DIRECT_SI_LABEL_ANCHOR]
    assert {c.observation_ref.fact_id for c in missing} == {middle.isa.observation_id, middle.rtl.observation_id}
    assert all(c.pc == middle.isa.pc for c in missing)
    assert len(context.si_anchors) == 2 and len(context.composed_anchors) == 4
    assert {s.instruction_ordinal for s in context.si_records} == {0, 3}
    assert not any(c.kind == U.ELF_TRACE_ANCHOR_UNAVAILABLE for c in context.unresolved_conditions)


def test_no_byte_anchor_is_preserved_as_missing(context_inputs, hardware_case):
    data = hardware_case.elf(word="00000093")
    context = build_trigger_candidate_context(**dict(context_inputs, elf_bytes=data, elf=parse_hardware_test_elf(data)))
    assert not context.trace_anchors and not context.composed_anchors and not context.si_records
    assert sum(c.kind == U.ELF_TRACE_ANCHOR_UNAVAILABLE for c in context.unresolved_conditions) == 6


def test_behavior_is_reference_only_via_frozen_anchors(context_inputs, hardware_case):
    fragment = hardware_case.fragment(context_inputs["raw_si"])
    context = build_trigger_candidate_context(**context_inputs, behavior_fragment=fragment)
    assert len(context.declared_behaviors) == 2
    assert all(b.nature == "source_declared" and b.fragment_id == fragment.id for b in context.declared_behaviors)
    assert all(b.instruction_id in {e.id for e in fragment.elements} for b in context.declared_behaviors)
    assert K.SOURCE_DECLARED_BEHAVIOR in {r.kind for r in context.fact_index()}


@pytest.mark.parametrize("mutation", ["si_sha", "elf_bytes", "elf_view", "raw_si", "architecture", "wrong_divergence", "scope"])
def test_builder_detached_source_revalidation(context_inputs, hardware_case, mutation):
    inputs = dict(context_inputs)
    if mutation == "si_sha":
        source = inputs["source"].model_dump(mode="json")
        source["artifact"]["artifact_sha256"] = "0" * 64
        inputs["source"] = type(inputs["source"]).model_validate(source)
    elif mutation == "elf_bytes":
        inputs["elf_bytes"] = hardware_case.elf(word="00000093")
    elif mutation == "elf_view":
        inputs["elf"] = inputs["elf"].model_copy(update={"entry_address": {"value": "0x900"}})
    elif mutation == "raw_si":
        inputs["raw_si"] = inputs["raw_si"].model_copy(update={"snapshot_sha256": "0" * 64})
    elif mutation == "architecture":
        source = inputs["source"].model_dump(mode="json")
        source["artifact"]["architecture"] = "arm"
        source["hardware_target"]["architecture"] = "arm"
        inputs["source"] = type(inputs["source"]).model_validate(source)
    else:
        isa, rtl = hardware_case.csv(), hardware_case.rtl(state=3)
        scope = AlignmentScope(isa_source=isa.source, rtl_source=rtl.source,
            common_start_pc={"value": "0x200"}, comparable_fields=(ComparableField.MSTATUS,))
        other = align_common_program(scope, isa, rtl)
        if mutation == "wrong_divergence":
            inputs["divergence"] = DivergenceObservation(aligned_pair=other.aligned_pairs[1], field="mstatus")
        else:
            inputs["alignment"] = inputs["alignment"].model_copy(update={"scope": scope})
    with pytest.raises(ValueError):
        build_trigger_candidate_context(**inputs)


@pytest.mark.parametrize("collection", ["context_records", "si_records", "si_anchors", "trace_anchors", "composed_anchors", "unresolved_conditions"])
def test_duplicate_context_entries_fail(context, collection):
    data = context.model_dump(mode="json")
    data[collection].append(data[collection][0])
    with pytest.raises(ValueError):
        HardwareTriggerCandidateContext.model_validate(data)


@pytest.mark.parametrize("mutation", ["scope", "observation_source", "ordinal", "comparison", "divergence_pair", "divergence_field",
    "si_source", "si_record", "si_sha", "trace_source", "trace_observation", "trace_pc", "trace_bytes", "composed_endpoint", "missing_condition"])
def test_compact_snapshot_internal_closure(context, mutation):
    data = context.model_dump(mode="json")
    pair = data["context_records"][0]
    if mutation == "scope": pair["alignment_scope_id"] = "different-scope"
    elif mutation == "observation_source": pair["isa"]["source_id"] = "different-source"
    elif mutation == "ordinal": pair["alignment_ordinal"] = 6
    elif mutation == "comparison": pair["comparisons"] = []
    elif mutation == "divergence_pair": data["divergence"]["pair_id"] = "different-pair"
    elif mutation == "divergence_field": data["divergence"]["field"] = "frm"
    elif mutation == "si_source": data["si_anchors"][0]["elf_source_id"] = "different-elf"
    elif mutation == "si_record": data["si_anchors"][0]["si_record_id"] = "different-record"
    elif mutation == "si_sha": data["si_anchors"][0]["si_sha256"] = "1" * 64
    elif mutation == "trace_source": data["trace_anchors"][0]["trace_source_id"] = "different-source"
    elif mutation == "trace_observation": data["trace_anchors"][0]["observation_id"] = "different-observation"
    elif mutation == "trace_pc": data["trace_anchors"][0]["pc"]["value"] = "0x300"
    elif mutation == "trace_bytes": data["trace_anchors"][0]["elf_file_bytes"] = "00000000"
    elif mutation == "composed_endpoint": data["composed_anchors"][0]["si_anchor_id"] = "different-anchor"
    else: data["unresolved_conditions"].pop()
    with pytest.raises(ValueError):
        HardwareTriggerCandidateContext.model_validate(data)


def test_equal_comparison_ids_require_pair_ownership(context):
    refs = [r for r in context.fact_index() if r.kind == K.FIELD_COMPARISON]
    same = [r for r in refs if r.fact_id == refs[0].fact_id]
    assert len(same) == 3 and len({r.owner_id for r in same}) == 3


def test_context_set_order_does_not_change_id(context):
    data = context.model_dump(mode="json")
    for name in ("si_records", "si_anchors", "trace_anchors", "composed_anchors", "unresolved_conditions"):
        data[name].reverse()
    assert HardwareTriggerCandidateContext.model_validate(data).id == context.id


@pytest.mark.parametrize("mutation", [{"kind": "RESOLVED"}, {"alignment_scope_id": "/tmp/file"}, {"resolved": True}, {"pc": {"value": "0x0"}}])
def test_unresolved_is_closed_and_not_false_zero(context, mutation):
    condition = next(c for c in context.unresolved_conditions if c.kind == U.HARDWARE_REVISION_UNKNOWN)
    assert condition.pc is None and condition.observation_ref is None
    assert UnresolvedCondition.model_validate_json(condition.model_dump_json()).id == condition.id
    with pytest.raises(ValidationError):
        UnresolvedCondition.model_validate(dict(condition.model_dump(mode="json"), **mutation))


def test_builder_never_constructs_requirements_or_parses_si(context_inputs, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("context construction must not extract requirements or invoke an SI parser/mapper")
    monkeypatch.setattr("chipchain.trigger.HardwareTriggerSpec.__init__", forbidden)
    monkeypatch.setattr("chipchain.trigger.InstructionTriggerRequirement.__init__", forbidden)
    monkeypatch.setattr("chipchain.adapters.processorfuzz.parser.parse_processorfuzz_si", forbidden)
    monkeypatch.setattr("chipchain.adapters.processorfuzz.mapper.map_processorfuzz_si", forbidden)
    result = build_trigger_candidate_context(**context_inputs)
    assert "proposed_requirements" not in type(result).model_fields


@pytest.mark.parametrize("label", ["/tmp/file", "C:\\local\\file", "~/file", "name\tlog"])
def test_context_does_not_leak_paths_from_broader_core_labels(context_inputs, label):
    data = context_inputs["source"].model_dump(mode="json")
    data["hardware_target"]["hardware_model"] = label
    source = type(context_inputs["source"]).model_validate(data)
    with pytest.raises(ValueError, match="source labels"):
        build_trigger_candidate_context(**dict(context_inputs, source=source))


def test_explicit_revision_is_not_replaced_with_unknown(context_inputs):
    data = context_inputs["source"].model_dump(mode="json")
    data["hardware_target"]["hardware_revision"] = "synthetic-revision-one"
    source = type(context_inputs["source"]).model_validate(data)
    context = build_trigger_candidate_context(**dict(context_inputs, source=source))
    assert all(c.kind != U.HARDWARE_REVISION_UNKNOWN for c in context.unresolved_conditions)
    assert context.source.hardware_target.hardware_revision == "synthetic-revision-one"
