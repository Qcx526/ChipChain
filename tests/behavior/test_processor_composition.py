"""Owned contract constructions only; no decoder, trace acquisition or evidence."""

import pytest
from pydantic import ValidationError

from chipchain.behavior.processor import (
    BehaviorFactNature, BehaviorRelation, BehaviorSourceContext, InstructionBehavior,
    ProcessorBehaviorFragment, ProcessorEvent,
)
from chipchain.core import deterministic_id


def binding(source, nature):
    return dict(source_context_id=source.id, architecture=source.architecture, nature=nature)


def static_fragment(firmware, source_kind="firmware_artifact"):
    source = BehaviorSourceContext(
        source_kind=source_kind, artifact=firmware.provenance,
        hardware_target=firmware.hardware_target, firmware=firmware,
        producer_profile_id="synthetic-static-contract-v1",
    )
    instructions = [InstructionBehavior(
        **binding(source, "static_decoded"), source_ordinal=i, mnemonic="synthetic_op",
    ) for i in (0, 1)]
    relations = [BehaviorRelation(
        **binding(source, "static_inferred"), source_id=instructions[0].id,
        target_id=instructions[1].id, relation=kind,
    ) for kind in ("static_cfg_successor", "data_dependency", "control_dependency")]
    return ProcessorBehaviorFragment(source=source, elements=instructions, relations=relations)


@pytest.mark.parametrize("source_kind", ["firmware_artifact", "static_analysis_artifact"])
def test_one_firmware_context_mixes_decoded_and_inferred(processor_firmware, source_kind):
    result = static_fragment(processor_firmware, source_kind)
    assert "nature" not in result.source.model_dump()
    assert len(result.elements) == 2 and len(result.relations) == 3
    assert {item.nature for item in result.elements} == {BehaviorFactNature.STATIC_DECODED}
    assert {item.nature for item in result.relations} == {BehaviorFactNature.STATIC_INFERRED}
    assert {item.source_context_id for item in (*result.elements, *result.relations)} == {result.source.id}
    restored = ProcessorBehaviorFragment.model_validate_json(result.model_dump_json())
    assert restored.id == result.id
    assert restored.id == deterministic_id("v2-processor-behavior-fragment-v1", restored.model_dump(mode="json"))
    assert ProcessorBehaviorFragment(source=result.source, elements=result.elements[::-1],
                                     relations=result.relations[::-1]).id == result.id


@pytest.mark.parametrize("change", ["producer", "source_hash", "target", "revision", "architecture", "firmware_hash"])
def test_mixed_nature_does_not_allow_different_context(processor_firmware, change):
    result = static_fragment(processor_firmware)
    payload = result.source.model_dump(mode="json")
    if change == "producer":
        payload["producer_profile_id"] = "other-producer"
    elif change in {"source_hash", "firmware_hash"}:
        payload["artifact"]["artifact_sha256"] = "c" * 64
        payload["firmware"]["provenance"]["artifact_sha256"] = "c" * 64
    elif change in {"target", "revision"}:
        field = "target_id" if change == "target" else "hardware_revision"
        payload["hardware_target"][field] = "other-target-value"
        payload["firmware"]["hardware_target"][field] = "other-target-value"
    else:
        payload["hardware_target"]["architecture"] = "arm"
        payload["artifact"]["architecture"] = "arm"
        payload["firmware"]["hardware_target"]["architecture"] = "arm"
        payload["firmware"]["provenance"]["architecture"] = "arm"
    other = BehaviorSourceContext.model_validate(payload)
    assert other.id != result.source.id
    with pytest.raises(ValidationError, match="source context mismatch"):
        ProcessorBehaviorFragment(source=other, elements=result.elements, relations=result.relations)


def test_cross_architecture_record_in_same_context_rejected(processor_firmware):
    result = static_fragment(processor_firmware)
    alien = InstructionBehavior.model_validate({**result.elements[0].model_dump(), "architecture": "arm"})
    with pytest.raises(ValidationError, match="architecture mismatch"):
        ProcessorBehaviorFragment(source=result.source, elements=[alien])


def occurrence(source, ordinal, instruction_id=None, nature="synthetic_fixture"):
    return ProcessorEvent(
        **binding(source, nature), instruction_id=instruction_id, effect_index=0,
        occurrence_ordinal=ordinal, event="other_declared", cause_id="synthetic-occurrence",
    )


def runtime_edge(source, left, right, nature="synthetic_fixture"):
    return BehaviorRelation(**binding(source, nature), relation="runtime_precedes",
                            source_id=left.id, target_id=right.id)


def runtime_loop(source):
    # Synthetic instruction descriptions, not actual STATIC_DECODED outputs.
    a, b = [InstructionBehavior(**binding(source, "synthetic_fixture"),
                               source_ordinal=i, mnemonic=name)
            for i, name in enumerate(("synthetic_A", "synthetic_B"))]
    events = [occurrence(source, i, inst.id) for i, inst in enumerate((a, b, a, b), 1)]
    edges = [runtime_edge(source, left, right) for left, right in zip(events, events[1:])]
    return [a, b], events, edges


def test_repeated_instruction_occurrences_form_sequence_not_cycle(source_context):
    instructions, events, edges = runtime_loop(source_context)
    result = ProcessorBehaviorFragment(source=source_context, elements=instructions + events, relations=edges)
    assert len({event.id for event in events}) == 4
    assert [event.occurrence_ordinal for event in events] == [1, 2, 3, 4]
    assert events[0].instruction_id == events[2].instruction_id == instructions[0].id
    assert events[1].instruction_id == events[3].instruction_id == instructions[1].id
    assert {event.effect_index for event in events} == {0}  # Not repurposed as execution count.
    assert all(event.id != event.instruction_id for event in events)
    assert len(result.elements) == 6 and len(result.relations) == 3
    assert ProcessorBehaviorFragment.model_validate_json(result.model_dump_json()).id == result.id
    for event in events:
        assert event.id == deterministic_id("v2-processor-event-v1", event.model_dump(mode="json"))
        assert ProcessorEvent.model_validate_json(event.model_dump_json()).id == event.id
    with pytest.raises(ValidationError, match="reference itself"):
        runtime_edge(source_context, events[0], events[0])
    with pytest.raises(ValidationError, match="cyclic order"):
        ProcessorBehaviorFragment(source=source_context, elements=instructions + events,
                                  relations=edges + [runtime_edge(source_context, events[-1], events[0])])


@pytest.mark.parametrize("nature", ["static_decoded", "static_inferred", "source_declared"])
def test_non_runtime_nature_cannot_claim_occurrence(source_context, nature):
    with pytest.raises(ValidationError, match="requires runtime or synthetic"):
        occurrence(source_context, 1, nature=nature)


@pytest.mark.parametrize("ordinal", [-1, True, "1", 1.5])
def test_occurrence_ordinal_strict_nonnegative(source_context, ordinal):
    with pytest.raises(ValidationError):
        occurrence(source_context, ordinal)


def test_runtime_observed_requires_explicit_occurrence(source_context):
    source = BehaviorSourceContext.model_validate({**source_context.model_dump(),
                                                 "source_kind": "runtime_observation_artifact"})
    first, second = [occurrence(source, i, nature="runtime_observed") for i in (1, 2)]
    result = ProcessorBehaviorFragment(source=source, elements=[first, second],
                                      relations=[runtime_edge(source, first, second, "runtime_observed")])
    assert len(result.relations) == 1  # Declared observation contract only, no trace backend.
    with pytest.raises(ValidationError, match="requires occurrence_ordinal"):
        ProcessorEvent.model_validate({**first.model_dump(), "occurrence_ordinal": None})
    with pytest.raises(ValidationError, match="incompatible with source kind"):
        ProcessorBehaviorFragment(source=source, elements=[occurrence(source, 1)])


def test_occurrence_ordinal_unique_across_instruction_and_effect_slots(source_context):
    instructions, events, _ = runtime_loop(source_context)
    duplicate = ProcessorEvent.model_validate({**events[1].model_dump(),
                                             "occurrence_ordinal": 1, "effect_index": 5})
    with pytest.raises(ValidationError, match="duplicate source-local occurrence ordinal"):
        ProcessorBehaviorFragment(source=source_context, elements=instructions + [events[0], duplicate])


@pytest.mark.parametrize("endpoint_kind", ["instruction", "event_without_occurrence"])
def test_runtime_precedes_requires_occurrence_endpoints(source_context, endpoint_kind):
    instructions, events, _ = runtime_loop(source_context)
    endpoint = instructions[0] if endpoint_kind == "instruction" else ProcessorEvent.model_validate({
        **events[0].model_dump(), "occurrence_ordinal": None,
    })
    elements = instructions + [events[1]]
    if endpoint_kind != "instruction":
        elements.append(endpoint)
    with pytest.raises(ValidationError, match="endpoints must be dynamic ProcessorEvent"):
        ProcessorBehaviorFragment(source=source_context, elements=elements,
                                  relations=[runtime_edge(source_context, endpoint, events[1])])


def test_static_decoded_instructions_cannot_be_runtime_order(processor_firmware):
    result = static_fragment(processor_firmware)
    for nature in ("runtime_observed", "synthetic_fixture"):
        edge = runtime_edge(result.source, *result.elements, nature=nature)
        with pytest.raises(ValidationError, match="incompatible with source kind"):
            ProcessorBehaviorFragment(source=result.source, elements=result.elements, relations=[edge])


def test_occurrence_ordinal_does_not_generate_order(source_context):
    events = [occurrence(source_context, i) for i in (1, 2)]
    assert ProcessorBehaviorFragment(source=source_context, elements=events).relations == ()


def test_runtime_occurrences_detached_from_caller_mutation(source_context):
    instructions, events, edges = runtime_loop(source_context)
    elements = instructions + events
    kept = ProcessorBehaviorFragment(source=source_context, elements=elements, relations=edges)
    before, identity = kept.model_dump_json(), kept.id
    elements.clear()
    edges.clear()
    object.__setattr__(events[0], "occurrence_ordinal", -1)
    object.__setattr__(source_context, "producer_profile_id", "caller-mutation")
    assert kept.model_dump_json() == before and kept.id == identity
    with pytest.raises(ValidationError):
        ProcessorBehaviorFragment(source=kept.source, elements=[events[0]])
    payload = kept.model_dump(mode="json")
    restored = ProcessorBehaviorFragment.model_validate(payload)
    event_payload = next(item for item in payload["elements"] if item["kind"] == "processor_event")
    event_payload["occurrence_ordinal"] = 999
    payload["relations"].clear()
    payload["source"]["producer_profile_id"] = "caller-mutation"
    assert restored.model_dump_json() == before and restored.id == identity
    event = next(item for item in restored.elements if isinstance(item, ProcessorEvent))
    with pytest.raises(ValidationError, match="frozen_instance"):
        event.occurrence_ordinal = 999
