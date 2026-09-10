"""Synthetic hardware-side anchors: neither compilation nor causal proof."""

import builtins
from pathlib import Path
import socket
import subprocess

import pytest
from pydantic import ValidationError

from chipchain.core import Architecture
from chipchain.adapters.hardware_case import parse_signature
from chipchain.evidence import TraceSourceSide
from chipchain.anchors import (
    AnchorError, AmbiguousSymbolError, MissingSymbolError, HardwareCaseInstructionAnchor,
    anchor_si_label, anchor_trace_instruction, compose_hardware_case_anchor, parse_hardware_test_elf,
)


def test_exact_label_and_optional_source_declared_binding(hardware_case, elf_snapshot):
    view, data = elf_snapshot
    raw = hardware_case.si()
    fragment = hardware_case.fragment(raw)
    anchor = anchor_si_label(raw, view, data, si_record_id=raw.instructions[0].id, behavior_fragment=fragment)
    assert anchor.si_sha256 == raw.snapshot_sha256 and anchor.si_snapshot_id == raw.id
    assert anchor.symbol.name == anchor.si_record.label == "_p0"
    assert anchor.elf_address.value == "0x200"
    assert anchor.elf_source == view.source
    assert anchor.behavior_binding.fragment_id == fragment.id
    assert anchor.behavior_binding.instruction.source_ordinal == 0
    assert anchor.behavior_binding.instruction.id in {item.id for item in fragment.elements}
    assert anchor.behavior_binding.instruction.nature.value == "source_declared"
    assert anchor.behavior_binding.context.firmware is None
    assert anchor.evidence_level.value == "CROSS_ARTIFACT_CORRELATED"


def test_missing_and_unlabeled_records_stay_unanchored(hardware_case):
    data = hardware_case.elf(symbols=[("_p0", 0x200, 1)])
    view = parse_hardware_test_elf(data)
    raw = hardware_case.si()
    with pytest.raises(MissingSymbolError):
        anchor_si_label(raw, view, data, si_record_id=raw.instructions[2].id)
    with pytest.raises(AnchorError):
        anchor_si_label(raw, view, data, si_record_id=raw.instructions[1].id)
    first = anchor_si_label(raw, view, data, si_record_id=raw.instructions[0].id)
    assert first.si_record.instruction_ordinal == 0
    assert not hasattr(first, "following_instruction_addresses")
    assert raw.instructions[1].label is None


@pytest.mark.parametrize("symbols", [
    [("_p0", 0x200, 1), ("_p0", 0x200, 1)],
    [("_p0", 0x200, 1), ("_p0", 0x204, 1)],
    [("_p0", 0x200, 1), ("_p0", 0, 0)],
])
def test_duplicate_symbol_occurrences_fail_closed(hardware_case, symbols):
    data = hardware_case.elf(symbols=symbols)
    with pytest.raises(AmbiguousSymbolError):
        anchor_si_label(hardware_case.si(), parse_hardware_test_elf(data), data, si_record_id=hardware_case.si().instructions[0].id)


@pytest.mark.parametrize("symbol", [("_p00", 0x200, 1), ("_p0", 0, 0), ("_p0", 0x200, 0xfff1), ("_p0", 0x300, 1)])
def test_symbol_match_must_be_exact_defined_and_in_section(hardware_case, symbol):
    data = hardware_case.elf(symbols=[symbol])
    raw = hardware_case.si()
    with pytest.raises(MissingSymbolError):
        anchor_si_label(raw, parse_hardware_test_elf(data), data, si_record_id=raw.instructions[0].id)


def test_tampered_si_or_elf_not_sufficient(hardware_case, elf_snapshot):
    view, data = elf_snapshot
    raw = hardware_case.si()
    record_id = raw.instructions[0].id
    for bad in (raw.model_copy(update={"snapshot_sha256": "0" * 64}),
                raw.model_copy(update={"instructions": (raw.instructions[0].model_copy(update={"label": "_p9"}), *raw.instructions[1:])})):
        with pytest.raises(ValueError):
            anchor_si_label(bad, view, data, si_record_id=record_id)
    forged = view.model_copy(update={"symbols": (view.symbols[0], view.symbols[1].model_copy(update={"value": 0x204}), *view.symbols[2:])})
    with pytest.raises(AnchorError):
        anchor_si_label(raw, forged, data, si_record_id=record_id)
    with pytest.raises(AnchorError):
        anchor_si_label(raw, view, data, si_record_id="absent-record")


def test_behavior_fragment_not_accepted_by_agreeing_ordinal_alone(hardware_case, elf_snapshot):
    view, data = elf_snapshot
    raw = hardware_case.si()
    fragment = hardware_case.fragment(raw)
    element = next(item for item in fragment.elements if item.source_ordinal == 0)
    replacement = element.model_copy(update={"mnemonic": "different"})
    # Empty relations avoid merely failing a dangling reference; mapper equality is required.
    forged = fragment.model_copy(update={"elements": tuple(replacement if item.id == element.id else item for item in fragment.elements), "relations": ()})
    with pytest.raises(ValueError):
        anchor_si_label(raw, view, data, si_record_id=raw.instructions[0].id, behavior_fragment=forged)
    another = hardware_case.si()
    from chipchain.adapters.processorfuzz import parse_processorfuzz_si
    other_raw = parse_processorfuzz_si(another.exact_bytes().replace(b"addi x1, zero, 0", b"addi x1, zero, 1"))
    with pytest.raises(ValueError):
        anchor_si_label(raw, view, data, si_record_id=raw.instructions[0].id, behavior_fragment=hardware_case.fragment(other_raw))


@pytest.mark.parametrize("side", ["csv", "rtl"])
def test_independent_trace_binding_without_state_equality(hardware_case, elf_snapshot, side):
    view, data = elf_snapshot
    trace = hardware_case.csv(state="1") if side == "csv" else hardware_case.rtl(state=7)
    anchor = anchor_trace_instruction(view, data, trace, observation_id=trace.observations[0].id)
    assert anchor.pc.value == "0x200" and anchor.instruction_encoding == "00000013"
    assert anchor.elf_file_bytes == "13000000"
    assert anchor.trace_source.id == trace.source.id
    assert anchor.observation.id == trace.observations[0].id
    assert type(anchor).model_validate_json(anchor.model_dump_json()).id == anchor.id


@pytest.mark.parametrize("word", ["00000033", "00000001", "0000001f"])
def test_wrong_encoding_and_unsupported_instruction_width(hardware_case, elf_snapshot, word):
    view, data = elf_snapshot
    trace = hardware_case.csv(word=word)
    with pytest.raises(AnchorError):
        anchor_trace_instruction(view, data, trace, observation_id=trace.observations[0].id)
    if word != "00000033":
        same_bytes = hardware_case.elf(word=word)
        # Even matching raw bytes cannot broaden this profile to compressed/long words.
        with pytest.raises(AnchorError):
            anchor_trace_instruction(parse_hardware_test_elf(same_bytes), same_bytes, trace, observation_id=trace.observations[0].id)


@pytest.mark.parametrize("pc", [0x100, 0x20a, 0x20c, 0x21c])
def test_non_file_backed_trace_pc_rejected(hardware_case, elf_snapshot, pc):
    view, data = elf_snapshot
    trace = hardware_case.csv(pcs=(pc,))
    with pytest.raises(AnchorError):
        anchor_trace_instruction(view, data, trace, observation_id=trace.observations[0].id)


def test_wrong_trace_profile_architecture_source_or_delayed_rejected(hardware_case, elf_snapshot):
    view, data = elf_snapshot
    signature = parse_signature((b"0" * 32 + b"\n") * 254, architecture=Architecture.RISC_V, source_side=TraceSourceSide.ISA_SIDE)
    with pytest.raises(AnchorError):
        anchor_trace_instruction(view, data, signature, observation_id=signature.observations[0].id)
    trace = hardware_case.rtl(delayed=True)
    with pytest.raises(AnchorError):
        anchor_trace_instruction(view, data, trace, observation_id=trace.observations[-1].id)
    with pytest.raises(AnchorError):
        anchor_trace_instruction(view, data, trace, observation_id=hardware_case.csv().observations[0].id)
    forged = trace.model_copy(update={"source": trace.source.model_copy(update={"architecture": Architecture.ARM})})
    with pytest.raises(ValueError):
        anchor_trace_instruction(view, data, forged, observation_id=trace.observations[0].id)
    with pytest.raises(AnchorError):
        anchor_trace_instruction(view, data[:-1] + b"\x01", trace, observation_id=trace.observations[0].id)


def test_composed_anchor_roundtrip_and_occurrence_identity(hardware_case, elf_snapshot):
    view, data = elf_snapshot
    raw = hardware_case.si()
    trace = hardware_case.csv(pcs=(0x200, 0x200))
    left = anchor_si_label(raw, view, data, si_record_id=raw.instructions[0].id)
    results = []
    for observation in trace.observations:
        right = anchor_trace_instruction(view, data, trace, observation_id=observation.id)
        result = compose_hardware_case_anchor(left, right, raw_si=raw, elf=view, elf_bytes=data, trace_artifact=trace)
        assert HardwareCaseInstructionAnchor.model_validate_json(result.model_dump_json()).id == result.id
        results.append(result)
    assert results[0].id != results[1].id
    assert results[0].trace_anchor.observation.record_ordinal == 0
    assert results[1].trace_anchor.observation.record_ordinal == 1


@pytest.mark.parametrize("mismatch", ["pc", "elf", "trace", "si"])
def test_composition_rejects_cross_source_or_address_mismatch(hardware_case, elf_snapshot, mismatch):
    view, data = elf_snapshot
    raw = hardware_case.si()
    trace = hardware_case.csv()
    left = anchor_si_label(raw, view, data, si_record_id=raw.instructions[0].id)
    right = anchor_trace_instruction(view, data, trace, observation_id=trace.observations[1 if mismatch == "pc" else 0].id)
    if mismatch == "elf":
        other_data = data[:-1] + b"\x01"
        right = anchor_trace_instruction(parse_hardware_test_elf(other_data), other_data, trace, observation_id=trace.observations[0].id)
    elif mismatch == "trace":
        trace = hardware_case.csv(state="2")
    elif mismatch == "si":
        left = left.model_copy(update={"si_sha256": "0" * 64})
    with pytest.raises(ValueError):
        compose_hardware_case_anchor(left, right, raw_si=raw, elf=view, elf_bytes=data, trace_artifact=trace)


def test_internally_consistent_forged_pair_cannot_be_recomposed(hardware_case, elf_snapshot):
    view, data = elf_snapshot
    raw, trace = hardware_case.si(), hardware_case.csv()
    left = anchor_si_label(raw, view, data, si_record_id=raw.instructions[0].id)
    right = anchor_trace_instruction(view, data, trace, observation_id=trace.observations[0].id)
    replacement = left.symbol.model_copy(update={"symbol_ordinal": 99})
    forged = type(left).model_validate(left.model_copy(update={"symbol": replacement}))
    # Internal declarations alone are not source authentication.
    with pytest.raises(AnchorError):
        compose_hardware_case_anchor(forged, right, raw_si=raw, elf=view, elf_bytes=data, trace_artifact=trace)


def test_no_file_subprocess_network_or_stale_disassembly_dependency(hardware_case, elf_snapshot, monkeypatch):
    view, data = elf_snapshot
    raw, trace = hardware_case.si(), hardware_case.csv()
    def forbidden(*args, **kwargs):
        raise AssertionError("anchor operation attempted external I/O")
    for target, name in ((builtins, "open"), (Path, "read_bytes"), (Path, "read_text"),
                         (subprocess, "Popen"), (socket, "socket")):
        monkeypatch.setattr(target, name, forbidden)
    left = anchor_si_label(raw, view, data, si_record_id=raw.instructions[0].id)
    right = anchor_trace_instruction(view, data, trace, observation_id=trace.observations[0].id)
    result = compose_hardware_case_anchor(left, right, raw_si=raw, elf=view, elf_bytes=data, trace_artifact=trace)
    assert result.si_anchor.elf_source.artifact_kind == "HARDWARE_TEST_PROGRAM_ELF"


@pytest.mark.parametrize("field", ["causal", "trigger", "critical", "necessary", "sufficient", "root_cause",
    "vulnerable", "verified", "exploit", "confidence", "firmware", "client_target", "generated_from", "compiled_from", "path", "timestamp", "run_id"])
def test_closed_non_causal_non_firmware_models(hardware_case, elf_snapshot, field):
    view, data = elf_snapshot
    raw, trace = hardware_case.si(), hardware_case.csv()
    left = anchor_si_label(raw, view, data, si_record_id=raw.instructions[0].id)
    right = anchor_trace_instruction(view, data, trace, observation_id=trace.observations[0].id)
    result = compose_hardware_case_anchor(left, right, raw_si=raw, elf=view, elf_bytes=data, trace_artifact=trace)
    for model in (left, right, result, view.source):
        assert field not in type(model).model_fields
        with pytest.raises(ValidationError):
            type(model).model_validate({**model.model_dump(), field: True})


def test_anchor_retains_detached_snapshots(hardware_case, elf_snapshot):
    view, data = elf_snapshot
    raw, trace = hardware_case.si(), hardware_case.csv()
    left = anchor_si_label(raw, view, data, si_record_id=raw.instructions[0].id)
    right = anchor_trace_instruction(view, data, trace, observation_id=trace.observations[0].id)
    result = compose_hardware_case_anchor(left, right, raw_si=raw, elf=view, elf_bytes=data, trace_artifact=trace)
    identity = result.id
    object.__setattr__(left.symbol, "value", 0x204)
    object.__setattr__(right.observation, "raw_line", "broken")
    assert result.id == identity
    with pytest.raises(ValidationError):
        result.si_anchor.symbol.value = 0x204


def test_optional_behavior_reference_must_be_reprovided_at_composition(hardware_case, elf_snapshot):
    view, data = elf_snapshot
    raw, trace = hardware_case.si(), hardware_case.csv()
    fragment = hardware_case.fragment(raw)
    left = anchor_si_label(raw, view, data, si_record_id=raw.instructions[0].id, behavior_fragment=fragment)
    right = anchor_trace_instruction(view, data, trace, observation_id=trace.observations[0].id)
    with pytest.raises(AnchorError):
        compose_hardware_case_anchor(left, right, raw_si=raw, elf=view, elf_bytes=data, trace_artifact=trace)
    result = compose_hardware_case_anchor(left, right, raw_si=raw, elf=view, elf_bytes=data,
                                         trace_artifact=trace, behavior_fragment=fragment)
    assert result.si_anchor.behavior_binding.fragment_id == fragment.id
    assert HardwareCaseInstructionAnchor.model_validate_json(result.model_dump_json()).id == result.id
