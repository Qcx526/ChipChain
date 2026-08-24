"""Offline exact PC-and-word matching for Phase 9C Step 3A."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from chipchain.hardware_trigger import (
    ArmExecutionMode,
    HardwareTriggerSignature,
    InvalidRuntimeTriggerInputError,
    RuntimeFirmwareTriggerMatcher,
    RuntimeInstructionOccurrence,
    RuntimeTriggerBindingError,
    RuntimeTriggerExecutionTrace,
    StaticFirmwareTriggerMatch,
    StaticFirmwareTriggerMatchResult,
    canonical_raw_instruction_bytes,
    raw_little_endian_a32_word,
)
from chipchain.models import Architecture
from chipchain.runtime.qemu import QemuTriggerRawTraceParser


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "phase9c" / "arm_a32_trigger_runtime"
RAW = (
    ROOT
    / "tests"
    / "fixtures"
    / "qemu_trigger_raw"
    / "valid_arm_a32_trigger_trace.jsonl"
)
GROUND_TRUTH = json.loads((FIXTURE / "ground_truth.json").read_text("utf-8"))
ARTIFACT_ID = str(GROUND_TRUTH["artifact_id"])
ARTIFACT_SHA256 = str(GROUND_TRUTH["artifact_sha256"])


def _static_result() -> StaticFirmwareTriggerMatchResult:
    signature = HardwareTriggerSignature.model_validate_json(
        (FIXTURE / "hardware_trigger_signature.json").read_text("utf-8")
    )
    matches = []
    for item in GROUND_TRUTH["static_occurrences"]:
        locations = [
            {
                "instruction_address": address,
                "instruction_word": word,
                "basic_block_address": item["function_address"],
            }
            for address, word in zip(
                item["instruction_addresses"],
                item["instruction_words"],
                strict=True,
            )
        ]
        match = StaticFirmwareTriggerMatch.create(
            artifact_id=ARTIFACT_ID,
            artifact_sha256=ARTIFACT_SHA256,
            signature_id=signature.id,
            hardware_vulnerability_id=signature.hardware_vulnerability_id,
            architecture=Architecture.ARM,
            execution_mode=ArmExecutionMode.A32,
            function_address=item["function_address"],
            function_name=item["function"],
            instruction_locations=locations,
            basic_block_path=[item["function_address"]],
            metadata={"fixture": True},
        )
        assert match.id == item["id"]
        matches.append(match)
    return StaticFirmwareTriggerMatchResult(
        artifact_id=ARTIFACT_ID,
        artifact_sha256=ARTIFACT_SHA256,
        signature_id=signature.id,
        hardware_vulnerability_id=signature.hardware_vulnerability_id,
        architecture=Architecture.ARM,
        execution_mode=ArmExecutionMode.A32,
        matches=matches,
        diagnostics=["fixture_static_result"],
    )


def _trace(
    instructions: list[RuntimeInstructionOccurrence] | None = None,
    *,
    artifact_id: str = ARTIFACT_ID,
    artifact_sha256: str = ARTIFACT_SHA256,
    raw_sha256: str | None = None,
    metadata: dict[str, object] | None = None,
) -> RuntimeTriggerExecutionTrace:
    parsed = QemuTriggerRawTraceParser().parse(RAW)
    normalized = instructions or [
        RuntimeInstructionOccurrence.create(
            sequence_index=item.sequence_index,
            pc=f"0x{int(item.pc.value, 16):08x}",
            instruction_size=item.instruction_size,
            instruction_bytes=item.instruction_bytes,
        )
        for item in parsed.events
    ]
    return RuntimeTriggerExecutionTrace.create(
        raw_trace_id=parsed.id,
        raw_trace_sha256=raw_sha256 or parsed.raw_trace_sha256,
        run_id=parsed.header.run_id,
        scenario_id="owned-phase9c-trigger-runtime-scenario",
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        architecture=Architecture.ARM,
        execution_mode=ArmExecutionMode.A32,
        instructions=normalized,
        metadata=metadata or {"fixture": True},
    )


def _event(index: int, pc: str, word: str, *, size: int = 4) -> RuntimeInstructionOccurrence:
    raw = int(word, 16).to_bytes(4, "little").hex() if size == 4 else "00" * size
    return RuntimeInstructionOccurrence.create(
        sequence_index=index,
        pc=pc,
        instruction_size=size,
        instruction_bytes=raw,
    )


def test_owned_trace_confirms_only_the_executed_static_occurrence() -> None:
    static = _static_result()
    result = RuntimeFirmwareTriggerMatcher().match(static, _trace())

    assert len(static.matches) == 2
    assert len(result.occurrences) == 1
    occurrence = result.occurrences[0]
    assert occurrence.static_match_id == GROUND_TRUTH["static_occurrences"][0]["id"]
    assert occurrence.static_match_id != GROUND_TRUTH["static_occurrences"][1]["id"]
    assert [item.pc for item in occurrence.instructions] == [
        "0x40200018",
        "0x4020001c",
        "0x40200020",
    ]
    assert [item.instruction_word for item in occurrence.instructions] == [
        "0xe3a00001",
        "0xe2801001",
        "0xe1a02001",
    ]


@pytest.mark.parametrize("change", ["word", "pc", "reorder", "gap", "prefix"])
def test_pc_word_order_gap_and_complete_length_are_all_mandatory(change: str) -> None:
    expected = GROUND_TRUTH["static_occurrences"][0]
    pairs = list(zip(expected["instruction_addresses"], expected["instruction_words"], strict=True))
    if change == "word":
        pairs[1] = (pairs[1][0], "0xe2801002")
    elif change == "pc":
        pairs[1] = ("0x4020002c", pairs[1][1])
    elif change == "reorder":
        pairs[1], pairs[2] = pairs[2], pairs[1]
    elif change == "gap":
        pairs.insert(1, ("0x40200010", "0xe1a00000"))
    else:
        pairs.pop()
    instructions = [_event(index, pc, word) for index, (pc, word) in enumerate(pairs)]

    result = RuntimeFirmwareTriggerMatcher().match(_static_result(), _trace(instructions))

    assert result.occurrences == []


def test_repeated_exact_sequence_returns_two_deterministic_occurrences() -> None:
    expected = GROUND_TRUTH["static_occurrences"][0]
    pairs = list(zip(expected["instruction_addresses"], expected["instruction_words"], strict=True)) * 2
    instructions = [_event(index, pc, word) for index, (pc, word) in enumerate(pairs)]

    first = RuntimeFirmwareTriggerMatcher().match(_static_result(), _trace(instructions))
    second = RuntimeFirmwareTriggerMatcher().match(_static_result(), _trace(instructions))

    executed_id = GROUND_TRUTH["static_occurrences"][0]["id"]
    confirmed = [item for item in first.occurrences if item.static_match_id == executed_id]
    assert len(confirmed) == 2
    assert second == first
    assert confirmed[0].id != confirmed[1].id


def test_non_four_byte_instruction_cannot_match_a32() -> None:
    expected = GROUND_TRUTH["static_occurrences"][0]
    instructions = [
        _event(index, pc, word, size=(2 if index == 1 else 4))
        for index, (pc, word) in enumerate(
            zip(expected["instruction_addresses"], expected["instruction_words"], strict=True)
        )
    ]
    assert RuntimeFirmwareTriggerMatcher().match(
        _static_result(), _trace(instructions)
    ).occurrences == []


def test_little_endian_conversion_and_raw_encoding_are_strict() -> None:
    assert raw_little_endian_a32_word("0100a0e3") == "0xe3a00001"
    assert canonical_raw_instruction_bytes("0100a0e3", size=4) == "0100a0e3"
    for invalid in ("0100A0E3", "0x0100a0e3", "01 00 a0 e3", "0100a0"):
        with pytest.raises(ValueError):
            canonical_raw_instruction_bytes(invalid, size=4)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("artifact_id", "different-firmware", "artifact ID mismatch"),
        ("artifact_sha256", "f" * 64, "firmware SHA-256 mismatch"),
    ],
)
def test_static_runtime_artifact_binding_fails_closed(
    field: str, value: str, message: str
) -> None:
    kwargs = {field: value}
    with pytest.raises(RuntimeTriggerBindingError, match=message):
        RuntimeFirmwareTriggerMatcher().match(_static_result(), _trace(**kwargs))


def test_detached_revalidation_rejects_static_and_runtime_semantic_tampering() -> None:
    static = _static_result()
    static.matches[0].instruction_locations[0].__dict__["instruction_word"] = "0xe3a00002"
    with pytest.raises(InvalidRuntimeTriggerInputError, match="revalidation"):
        RuntimeFirmwareTriggerMatcher().match(static, _trace())

    runtime = _trace()
    runtime.instructions[1].__dict__["instruction_bytes"] = "0200a0e3"
    with pytest.raises(InvalidRuntimeTriggerInputError, match="revalidation"):
        RuntimeFirmwareTriggerMatcher().match(_static_result(), runtime)


def test_occurrence_identity_binds_raw_content_but_excludes_metadata() -> None:
    first_trace = _trace(metadata={"label": "first"})
    second_trace = _trace(metadata={"label": "second"})
    changed_raw = hashlib.sha256(b"changed exact raw trace bytes").hexdigest()
    changed_trace = _trace(raw_sha256=changed_raw)

    first = RuntimeFirmwareTriggerMatcher().match(_static_result(), first_trace)
    second = RuntimeFirmwareTriggerMatcher().match(_static_result(), second_trace)
    changed = RuntimeFirmwareTriggerMatcher().match(_static_result(), changed_trace)

    assert first_trace.id == second_trace.id
    assert first.occurrences[0].id == second.occurrences[0].id
    assert first.occurrences[0].id != changed.occurrences[0].id


def test_zero_match_and_nonempty_preconditions_have_no_verdict_semantics() -> None:
    signature_with_preconditions = HardwareTriggerSignature.model_validate_json(
        (
            ROOT
            / "tests"
            / "fixtures"
            / "phase9c"
            / "arm_a32_hardware_trigger_signature.json"
        ).read_text("utf-8")
    )
    result = RuntimeFirmwareTriggerMatcher().match(
        _static_result(),
        _trace([_event(0, "0x40200018", "0xe3a00002")]),
    )
    serialized = result.model_dump(mode="json")

    assert signature_with_preconditions.preconditions.register_preconditions
    assert result.occurrences == []
    forbidden = {
        "verified",
        "triggerable",
        "preconditions_satisfied",
        "vulnerability_verified",
        "attack_chain_verified",
        "hardware_failure_reproduced",
        "score",
        "confidence",
        "status",
    }
    assert forbidden.isdisjoint(serialized)
    assert all("/" not in str(value) and "\\" not in str(value) for value in serialized.values())
