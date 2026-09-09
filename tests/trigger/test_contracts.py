"""Permanent synthetic requirement-contract regressions; no satisfaction tests."""

import json
from itertools import permutations

from pydantic import ValidationError
import pytest

import chipchain.trigger as public
from chipchain.core import Architecture, ProcessorFuzzArtifact, ProgramAddress
from chipchain.behavior.processor import ExactScalar, MemoryAddress
from chipchain.trigger import (
    AnyOperandRequirement, ControlTransferTriggerRequirement, EventTriggerRequirement,
    ExactScalarConstraint, HardwareTriggerSpec, InstructionTriggerRequirement, MaskedScalarConstraint,
    MemoryAccessTriggerRequirement, MemoryStateTriggerRequirement, PrivilegeStateTriggerRequirement,
    RegisterAccessTriggerRequirement, RegisterOperandRequirement, RegisterStateTriggerRequirement,
    ScalarOperandRequirement, TextOperandRequirement, TriggerOrderKind, TriggerOrderRequirement,
    TriggerSourceContext, TriggerSourceKind,
)


def instruction(source, slot=0, **fields):
    return InstructionTriggerRequirement(
        source_context_id=source.id, architecture=source.architecture,
        requirement_slot=slot, mnemonic="synthetic.a", **fields,
    )


def order(source, before, after, kind=TriggerOrderKind.REQUIRED_PRECEDES):
    return TriggerOrderRequirement(
        source_context_id=source.id, architecture=source.architecture, kind=kind,
        before_id=before, after_id=after,
    )


def replace(model, **fields):
    """Validated replacement; tests explicitly label any unchecked corruption below."""
    return type(model).model_validate({**model.model_dump(mode="python"), **fields})


def test_all_eight_requirements_and_roundtrip(spec):
    assert {type(item) for item in spec.preconditions} == {
        RegisterStateTriggerRequirement, MemoryStateTriggerRequirement, PrivilegeStateTriggerRequirement,
    }
    assert {type(item) for item in spec.steps} == {
        InstructionTriggerRequirement, RegisterAccessTriggerRequirement, MemoryAccessTriggerRequirement,
        ControlTransferTriggerRequirement, EventTriggerRequirement,
    }
    assert spec.source.source_kind == TriggerSourceKind.SYNTHETIC_FIXTURE
    assert HardwareTriggerSpec.model_validate_json(spec.model_dump_json()) == spec
    assert HardwareTriggerSpec.model_validate_json(spec.model_dump_json()).id == spec.id
    for item in (spec.source, *spec.preconditions, *spec.steps, *spec.order_requirements):
        assert type(item).model_validate_json(item.model_dump_json()).id == item.id
        assert item.id.split(":")[0].endswith("-v1")
        assert len(item.id.split(":")[-1]) == 64


def test_operands_none_empty_and_position(source, register_ref):
    unspecified = instruction(source)
    empty = instruction(source, operands=[])
    assert unspecified.operands is None and empty.operands == ()
    assert unspecified.id != empty.id
    operands = (
        AnyOperandRequirement(), RegisterOperandRequirement(register_ref=register_ref),
        ScalarOperandRequirement(constraint=ExactScalarConstraint(value=ExactScalar(width_bits=8, value="0x0"))),
        TextOperandRequirement(text="synthetic-operand"),
    )
    constrained = instruction(source, operands=operands)
    assert constrained.operands == operands
    assert instruction(source, operands=operands[::-1]).id != constrained.id
    assert len({item.id for item in operands}) == 4
    for operand in operands:
        assert type(operand).model_validate_json(operand.model_dump_json()).id == operand.id


def test_scalar_normalization_and_distinctions():
    exact = ExactScalarConstraint(value={"width_bits": 8, "value": "0X0002"})
    assert exact.value.value == "0x2"
    assert exact == ExactScalarConstraint(value={"width_bits": 8, "value": "0x2"})
    assert exact.id != ExactScalarConstraint(value={"width_bits": 16, "value": "0x2"}).id
    masked = MaskedScalarConstraint(value=exact.value, mask={"width_bits": 8, "value": "0x3"})
    assert masked.id != exact.id
    assert replace(masked, mask={"width_bits": 8, "value": "0x7"}).id != masked.id
    assert MaskedScalarConstraint.model_validate_json(masked.model_dump_json()).id == masked.id
    assert ExactScalarConstraint(value={"width_bits": 8, "value": "0x0"}).value.value == "0x0"


@pytest.mark.parametrize("value,mask", [
    ({"width_bits": 8, "value": "0x1"}, {"width_bits": 16, "value": "0x3"}),
    ({"width_bits": 8, "value": "0x100"}, {"width_bits": 8, "value": "0xff"}),
    ({"width_bits": 8, "value": "0x1"}, {"width_bits": 8, "value": "0x100"}),
    ({"width_bits": 8, "value": "0x4"}, {"width_bits": 8, "value": "0x3"}),
    ({"width_bits": 8, "value": "0x0"}, {"width_bits": 8, "value": "0x0"}),
])
def test_invalid_masked_constraints(value, mask):
    with pytest.raises(ValidationError):
        MaskedScalarConstraint(value=value, mask=mask)


@pytest.mark.parametrize("width", [0, -1, True, False, "8", 8.0])
@pytest.mark.parametrize("field", ["value", "mask"])
def test_scalar_widths_are_strict_positive(width, field):
    fields = {"value": {"width_bits": 8, "value": "0x1"}, "mask": {"width_bits": 8, "value": "0x3"}}
    fields[field]["width_bits"] = width
    with pytest.raises(ValidationError):
        MaskedScalarConstraint(**fields)
    with pytest.raises(ValidationError):
        ExactScalarConstraint(value=fields[field])


@pytest.mark.parametrize("value", [None, 0, True, "unknown", "symbolic", "-1", "1"])
def test_scalar_constraint_never_fabricates_values(value):
    with pytest.raises(ValidationError):
        ExactScalarConstraint(value={"width_bits": 8, "value": value})


@pytest.mark.parametrize("slot", [-1, True, False, "0", 0.0, None])
def test_slot_strictness(source, slot):
    with pytest.raises(ValidationError):
        instruction(source, slot)


def test_repeat_a_b_a_is_distinct_without_implicit_order(source):
    a0 = instruction(source, 0)
    b1 = replace(instruction(source, 1), mnemonic="synthetic.b")
    a2 = instruction(source, 2)
    spec = HardwareTriggerSpec(source=source, steps=[a0, b1, a2])
    assert len({item.id for item in spec.steps}) == 3
    assert spec.order_requirements == ()
    edges = [order(source, a0.id, b1.id), order(source, b1.id, a2.id)]
    ordered = replace(spec, order_requirements=edges)
    assert ordered.id != spec.id
    assert {item.requirement_slot for item in ordered.steps} == {0, 1, 2}
    assert {replace(spec, steps=list(items)).id for items in permutations(spec.steps)} == {spec.id}


def test_collection_order_does_not_change_identity(spec):
    permuted = replace(spec, steps=spec.steps[::-1], preconditions=spec.preconditions[::-1],
                       order_requirements=spec.order_requirements[::-1])
    assert permuted == spec and permuted.id == spec.id
    for field in ("steps", "preconditions", "order_requirements"):
        records = getattr(spec, field)
        with pytest.raises(ValidationError, match="duplicate"):
            replace(spec, **{field: [*records, records[0]]})


def test_duplicate_slot_same_and_different_kinds_rejected(source, spec):
    a = instruction(source)
    b = replace(a, mnemonic="synthetic.b")
    with pytest.raises(ValidationError, match="duplicate requirement_slot"):
        HardwareTriggerSpec(source=source, steps=[a, b])
    state = spec.preconditions[0]
    a = instruction(source, state.requirement_slot)
    with pytest.raises(ValidationError, match="duplicate requirement_slot"):
        HardwareTriggerSpec(source=source, preconditions=[state], steps=[a])


def test_preconditions_and_steps_cannot_be_swapped(spec):
    with pytest.raises(ValidationError):
        replace(spec, steps=spec.preconditions, preconditions=spec.steps)


def test_orders_are_explicit_and_typed(source):
    a, b = instruction(source, 99), instruction(source, 3)
    before = order(source, a.id, b.id)
    immediate = replace(before, kind=TriggerOrderKind.REQUIRED_IMMEDIATELY_PRECEDES)
    assert before.id != immediate.id
    # Descending/non-adjacent slot numbers do not prevent explicitly required adjacency.
    spec = HardwareTriggerSpec(source=source, steps=[a, b], order_requirements=[immediate])
    assert spec.order_requirements == (immediate,)
    for invalid in ("source_sequence", "static_cfg_successor", "runtime_precedes"):
        with pytest.raises(ValidationError):
            replace(before, kind=invalid)


@pytest.mark.parametrize("endpoint", ["dangling", "state", "foreign"])
@pytest.mark.parametrize("which", ["before_id", "after_id"])
def test_invalid_order_endpoint(source, spec, endpoint, which):
    a, b = instruction(source, 20), instruction(source, 21)
    foreign = instruction(source, 22)  # Belongs to another spec, absent from this one.
    foreign_spec = HardwareTriggerSpec(source=source, steps=[foreign])
    invalid = {"dangling": "absent-id", "state": spec.preconditions[0].id,
               "foreign": foreign_spec.steps[0].id}[endpoint]
    edge = replace(order(source, a.id, b.id), **{which: invalid})
    with pytest.raises(ValidationError, match="endpoints must be steps in this spec"):
        HardwareTriggerSpec(source=source, preconditions=spec.preconditions, steps=[a, b], order_requirements=[edge])


def test_self_order_rejected(source):
    a = instruction(source)
    with pytest.raises(ValidationError, match="self order"):
        order(source, a.id, a.id)


@pytest.mark.parametrize("kinds", [
    (TriggerOrderKind.REQUIRED_PRECEDES,) * 3,
    (TriggerOrderKind.REQUIRED_IMMEDIATELY_PRECEDES,) * 3,
    (TriggerOrderKind.REQUIRED_PRECEDES, TriggerOrderKind.REQUIRED_IMMEDIATELY_PRECEDES,
     TriggerOrderKind.REQUIRED_PRECEDES),
])
@pytest.mark.parametrize("length", [2, 3])
def test_precedence_cycles_fail_closed(source, kinds, length):
    steps = [instruction(source, slot) for slot in range(length)]
    edges = [order(source, steps[i].id, steps[(i + 1) % length].id, kinds[i]) for i in range(length)]
    with pytest.raises(ValidationError, match="cyclic"):
        HardwareTriggerSpec(source=source, steps=steps, order_requirements=edges)


@pytest.mark.parametrize("requirement_type", [RegisterAccessTriggerRequirement, RegisterStateTriggerRequirement])
def test_nested_register_architecture_rejected(spec, register_ref, requirement_type):
    other = Architecture.ARM if register_ref.architecture == Architecture.RISC_V else Architecture.RISC_V
    bad_register = replace(register_ref, architecture=other)
    requirement = next(item for item in (*spec.preconditions, *spec.steps) if isinstance(item, requirement_type))
    with pytest.raises(ValidationError, match="architecture mismatch"):
        replace(requirement, register_ref=bad_register)
    with pytest.raises(ValidationError, match="architecture mismatch"):
        instruction(spec.source, operands=[RegisterOperandRequirement(register_ref=bad_register)])


@pytest.mark.parametrize("collection", ["steps", "preconditions", "order_requirements"])
@pytest.mark.parametrize("field", ["architecture", "source_context_id"])
def test_every_member_is_source_bound(spec, collection, field):
    other = Architecture.ARM if spec.source.architecture == Architecture.RISC_V else Architecture.RISC_V
    records = list(getattr(spec, collection))
    # Use no-register records so standalone validation succeeds before spec binding checks.
    index = next(i for i, item in enumerate(records) if not isinstance(item, (
        RegisterStateTriggerRequirement, RegisterAccessTriggerRequirement, InstructionTriggerRequirement,
    )))
    records[index] = replace(records[index], **{field: other if field == "architecture" else "foreign-source"})
    with pytest.raises(ValidationError, match="mismatch"):
        replace(spec, **{collection: records})


def processor_fuzz_context(source):
    """Synthetic descriptor exercising PF binding, never a real PF finding."""
    pf = ProcessorFuzzArtifact(provenance=source.artifact, hardware_target=source.hardware_target)
    return replace(source, source_kind=TriggerSourceKind.PROCESSORFUZZ_ARTIFACT, processor_fuzz=pf)


def test_processor_fuzz_full_binding_and_unknown_preservation(source):
    context = processor_fuzz_context(source)
    assert context.processor_fuzz.provenance == context.artifact
    assert context.processor_fuzz.hardware_target == context.hardware_target
    assert context.producer_profile_id == context.processor_fuzz.provenance.producer_profile_id
    assert context.hardware_target.hardware_revision is None
    assert context.hardware_target.instruction_set_profile_id is None
    assert HardwareTriggerSpec(source=context).steps == ()  # No automatic extraction.
    assert context.id != source.id
    assert TriggerSourceContext.model_validate_json(context.model_dump_json()).id == context.id


@pytest.mark.parametrize("field,value", [
    ("target_id", "other-target"), ("hardware_model", "Other model"),
    ("hardware_revision", "other-revision"), ("instruction_set_profile_id", "other-isa-profile"),
])
def test_processor_fuzz_target_mismatch(source, field, value):
    context = processor_fuzz_context(source)
    with pytest.raises(ValidationError, match="hardware target mismatch"):
        replace(context, hardware_target=replace(context.hardware_target, **{field: value}))


@pytest.mark.parametrize("field,value", [
    ("artifact_id", "other-artifact"), ("artifact_sha256", "b" * 64),
    ("source_kind", "other-source-kind"), ("producer_profile_id", "other-producer"),
])
def test_processor_fuzz_provenance_mismatch(source, field, value):
    context = processor_fuzz_context(source)
    changes = {"artifact": replace(context.artifact, **{field: value})}
    if field == "producer_profile_id":
        changes["producer_profile_id"] = value
    with pytest.raises(ValidationError, match="provenance mismatch"):
        replace(context, **changes)


def test_source_binding_required_and_architecture_explicit(source):
    with pytest.raises(ValidationError, match="binding required"):
        replace(source, source_kind=TriggerSourceKind.PROCESSORFUZZ_ARTIFACT)
    context = processor_fuzz_context(source)
    with pytest.raises(ValidationError, match="binding required"):
        replace(context, source_kind=TriggerSourceKind.SYNTHETIC_FIXTURE)
    with pytest.raises(ValidationError, match="producer profile mismatch"):
        replace(context, producer_profile_id="other-profile")
    for architecture in (None, Architecture.ARM if source.architecture == Architecture.RISC_V else Architecture.RISC_V):
        with pytest.raises(ValidationError, match="target architecture"):
            replace(source, artifact=replace(source.artifact, architecture=architecture))


def test_different_target_changes_source_binding(source):
    other_source = replace(source, hardware_target=replace(source.hardware_target, hardware_revision="synthetic-v2"))
    assert other_source.id != source.id
    with pytest.raises(ValidationError, match="source context mismatch"):
        HardwareTriggerSpec(source=other_source, steps=[instruction(source)])
    assert instruction(other_source).id != instruction(source).id


def test_access_state_and_event_boundaries(spec):
    access = next(item for item in spec.steps if isinstance(item, RegisterAccessTriggerRequirement))
    with pytest.raises(ValidationError):
        replace(access, value={"width_bits": 8, "value": "0x0"})
    memory = next(item for item in spec.steps if isinstance(item, MemoryAccessTriggerRequirement))
    assert memory.memory_address is None and memory.width_bytes is None
    constrained = replace(memory, width_bytes=2, memory_address=MemoryAddress(value="0x0"))
    assert constrained.id != memory.id
    for width in (0, -1, True, "2", 2.0):
        with pytest.raises(ValidationError):
            replace(memory, width_bytes=width)
    state = next(item for item in spec.preconditions if isinstance(item, MemoryStateTriggerRequirement))
    for address in (None, "unknown", {"value": "symbolic"}, ProgramAddress(value="0x0")):
        with pytest.raises(ValidationError):
            replace(state, memory_address=address)
    for constraint in (None, {"kind": "unknown"}):
        with pytest.raises(ValidationError):
            replace(state, constraint=constraint)
    transfer = next(item for item in spec.steps if isinstance(item, ControlTransferTriggerRequirement))
    assert transfer.target is None
    assert replace(transfer, target=ProgramAddress(value="0x100")).id != transfer.id
    with pytest.raises(ValidationError):
        replace(transfer, target=MemoryAddress(value="0x100"))
    event = next(item for item in spec.steps if isinstance(item, EventTriggerRequirement))
    assert event.cause_id is None
    assert replace(event, cause_id="synthetic-cause").id != event.id


def test_detached_inputs_preserve_spec_and_id(spec):
    payload = spec.model_dump(mode="json")
    retained = HardwareTriggerSpec.model_validate(payload)
    original_json, original_id = retained.model_dump_json(), retained.id
    payload["source"]["hardware_target"]["hardware_model"] = "Changed input"
    payload["steps"].clear()
    payload["preconditions"].clear()
    payload["order_requirements"][0]["before_id"] = "changed"
    assert retained.model_dump_json() == original_json and retained.id == original_id

    source = spec.source
    state = next(item for item in spec.preconditions if isinstance(item, RegisterStateTriggerRequirement))
    relation = spec.order_requirements[0]
    retained = HardwareTriggerSpec(source=source, preconditions=spec.preconditions,
                                   steps=spec.steps, order_requirements=spec.order_requirements)
    original_json, original_id = retained.model_dump_json(), retained.id
    assert retained.source is not source
    assert retained.source.hardware_target is not source.hardware_target
    # Deliberately bypass caller objects' frozen guard to demonstrate detached nested snapshots.
    object.__setattr__(source.hardware_target, "hardware_model", "Changed caller")
    object.__setattr__(state.constraint.value, "value", "0xff")
    object.__setattr__(relation, "before_id", "changed")
    assert retained.model_dump_json() == original_json and retained.id == original_id


def test_unchecked_nested_updates_are_revalidated(spec):
    instruction_node = next(item for item in spec.steps if isinstance(item, InstructionTriggerRequirement))
    malformed = instruction_node.model_copy(update={"requirement_slot": True})
    with pytest.raises(ValidationError):
        HardwareTriggerSpec(source=spec.source, steps=[malformed])
    state = next(item for item in spec.preconditions if isinstance(item, RegisterStateTriggerRequirement))
    malformed_value = state.constraint.value.model_copy(update={"value": "0xff"})
    malformed_constraint = state.constraint.model_copy(update={"value": malformed_value})
    malformed_state = state.model_copy(update={"constraint": malformed_constraint})
    with pytest.raises(ValidationError, match="outside mask"):
        HardwareTriggerSpec(source=spec.source, preconditions=[malformed_state])
    edge = spec.order_requirements[0]
    malformed_edge = edge.model_copy(update={"after_id": edge.before_id})
    with pytest.raises(ValidationError, match="self order"):
        replace(spec, order_requirements=[malformed_edge])


def test_unchecked_source_and_whole_spec_are_revalidated(spec):
    context = processor_fuzz_context(spec.source)
    wrong_target = replace(context.hardware_target, hardware_revision="other-revision")
    malformed_context = context.model_copy(update={"hardware_target": wrong_target})
    with pytest.raises(ValidationError, match="hardware target mismatch"):
        HardwareTriggerSpec(source=malformed_context)
    wrong_provenance = replace(context.artifact, producer_profile_id="other-producer")
    malformed_pf = context.processor_fuzz.model_copy(update={"provenance": wrong_provenance})
    with pytest.raises(ValidationError, match="provenance mismatch"):
        HardwareTriggerSpec(source=context.model_copy(update={"processor_fuzz": malformed_pf}))
    repeated_steps = (*spec.steps, spec.steps[0])
    malformed_spec = spec.model_copy(update={"steps": repeated_steps})
    with pytest.raises(ValidationError, match="duplicate"):
        HardwareTriggerSpec.model_validate(malformed_spec)


def test_caller_operand_and_requirement_lists_detach(source):
    operands = [TextOperandRequirement(text="synthetic-original")]
    node = instruction(source, operands=operands)
    steps = [node]
    retained = HardwareTriggerSpec(source=source, steps=steps)
    original_id = retained.id
    operands.append(AnyOperandRequirement())
    steps.clear()
    object.__setattr__(node.operands[0], "text", "changed-caller")
    assert retained.steps[0].operands == (TextOperandRequirement(text="synthetic-original"),)
    assert retained.id == original_id


def test_source_and_order_v1_vocabularies_are_closed():
    source_schema = TriggerSourceContext.model_json_schema()["properties"]["source_kind"]
    order_schema = TriggerOrderRequirement.model_json_schema()["properties"]["kind"]
    assert source_schema["enum"] == ["processorfuzz_artifact", "synthetic_fixture"]
    assert order_schema["enum"] == ["required_precedes", "required_immediately_precedes"]


def test_frozen_fields_and_closed_spec_contract(spec):
    for item, field, value in (
        (spec, "steps", ()), (spec.source, "producer_profile_id", "changed"),
        (spec.steps[0], "requirement_slot", 100),
        (spec.order_requirements[0], "before_id", "changed"),
    ):
        with pytest.raises(ValidationError, match="frozen"):
            setattr(item, field, value)
    with pytest.raises(ValidationError):
        replace(spec, contract="v2_hardware_trigger_spec_v2")
    assert HardwareTriggerSpec.model_json_schema()["properties"]["contract"]["const"] == "v2_hardware_trigger_spec_v1"
    assert HardwareTriggerSpec(source=spec.source).steps == ()


@pytest.mark.parametrize("field", [
    "nature", "is_vulnerability", "is_verified", "satisfied", "match_result", "confidence_score",
    "reachable", "firmware_reachable", "runtime_occurrence_ordinal", "evidence", "id",
])
def test_no_verdict_fact_or_runtime_fields(spec, field):
    for item in (spec, spec.source, *spec.steps, *spec.preconditions, *spec.order_requirements):
        with pytest.raises(ValidationError):
            replace(item, **{field: "forbidden"})


def test_public_surface_has_no_extraction_satisfaction_or_private_helpers():
    forbidden = {"matches", "satisfies", "evaluate", "check_trigger", "is_met", "compare_behavior",
                 "extract_trigger", "reduce_trigger", "select_critical_instructions", "minimize_si",
                 "find_trigger_window"}
    assert not (set(dir(public)) & forbidden)
    assert not any(name.startswith("_") for name in public.__all__)
    for name in public.__all__:
        member = getattr(public, name)
        assert not (set(dir(member)) & forbidden)
    schema = json.dumps(HardwareTriggerSpec.model_json_schema())
    assert "BehaviorFactNature" not in schema
    assert "SOURCE_DECLARED" not in schema and "RUNTIME_OBSERVED" not in schema
