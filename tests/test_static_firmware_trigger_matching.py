"""Offline Phase 9C Step 2 exact static trigger-matching tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.analysis import ProgramArtifact
from chipchain.hardware_trigger import (
    AngrFirmwareTriggerMatcher,
    ArmExecutionMode,
    FirmwareTriggerMatcher,
    HardwareTriggerSignature,
    InvalidTriggerMatchingInputError,
    StaticFirmwareTriggerMatch,
    StaticFirmwareTriggerMatchResult,
    StaticInstructionLocation,
    UnsupportedTriggerArtifactError,
)
from chipchain.hardware_trigger.angr_matcher import _logical_a32_word
from chipchain.hardware_trigger.matcher import (
    _StaticBasicBlock,
    _StaticFunction,
    _StaticInstruction,
    _StaticProgramView,
    _match_program_view,
)
from chipchain.models import Architecture


SIGNATURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "phase9c"
    / "arm_a32_hardware_trigger_signature.json"
)
ARTIFACT_SHA256 = "a" * 64
WORDS = ("0xe3a00001", "0xe2801001", "0xe1a02001")


def _signature(
    words: tuple[str, ...] = WORDS,
) -> HardwareTriggerSignature:
    source = HardwareTriggerSignature.model_validate_json(
        SIGNATURE_PATH.read_text(encoding="utf-8")
    )
    return HardwareTriggerSignature.create(
        architecture=source.architecture,
        execution_mode=source.execution_mode,
        hardware_vulnerability_id=source.hardware_vulnerability_id,
        instruction_sequence=list(words),
        preconditions=source.preconditions,
        expected_effect=source.expected_effect,
        proof=source.proof,
        metadata=source.metadata,
    )


def _artifact(
    *,
    architecture: Architecture = Architecture.ARM,
    artifact_type: str = "elf",
    path: str | None = None,
) -> ProgramArtifact:
    return ProgramArtifact(
        id="synthetic-owned-phase9c-static-artifact",
        architecture=architecture,
        artifact_type=artifact_type,
        path=path,
        fixture_identifier="synthetic-owned-phase9c-static-view",
        metadata={"fixture": True, "synthetic": True, "owned": True},
    )


def _instruction(
    address: int,
    word: str,
    *,
    size: int = 4,
    is_a32: bool = True,
) -> _StaticInstruction:
    return _StaticInstruction(
        address=address,
        word=word,
        size=size,
        is_a32=is_a32,
    )


def _block(
    address: int,
    words: tuple[str, ...],
    *,
    function_address: int = 0x1000,
    cfg_successors: tuple[int, ...] = (),
    sequence_successors: tuple[int, ...] | None = None,
    is_a32: bool = True,
    instruction_size: int = 4,
) -> _StaticBasicBlock:
    return _StaticBasicBlock(
        address=address,
        function_address=function_address,
        instructions=tuple(
            _instruction(
                address + index * instruction_size,
                word,
                size=instruction_size,
                is_a32=is_a32,
            )
            for index, word in enumerate(words)
        ),
        cfg_successors=cfg_successors,
        sequence_successors=sequence_successors,
        is_a32=is_a32,
    )


def _function(
    blocks: tuple[_StaticBasicBlock, ...],
    *,
    address: int = 0x1000,
    entry: int = 0x1000,
    name: str = "synthetic_trigger_function",
) -> _StaticFunction:
    return _StaticFunction(
        address=address,
        name=name,
        entry_block_address=entry,
        blocks=blocks,
    )


def _result(
    view: _StaticProgramView,
    *,
    signature: HardwareTriggerSignature | None = None,
    artifact_sha256: str = ARTIFACT_SHA256,
) -> StaticFirmwareTriggerMatchResult:
    return _match_program_view(
        artifact=_artifact(),
        artifact_sha256=artifact_sha256,
        signature=signature or _signature(),
        view=view,
    )


def _one_block_view(words: tuple[str, ...]) -> _StaticProgramView:
    return _StaticProgramView(
        functions=(_function((_block(0x1000, words),)),)
    )


class _CapturingMatcher(FirmwareTriggerMatcher):
    """Test seam proving detached inputs before backend analysis."""

    def __init__(self) -> None:
        self.calls: list[tuple[ProgramArtifact, HardwareTriggerSignature]] = []

    def _match_detached(
        self,
        artifact: ProgramArtifact,
        signature: HardwareTriggerSignature,
    ) -> StaticFirmwareTriggerMatchResult:
        self.calls.append((artifact, signature))
        return _match_program_view(
            artifact=artifact,
            artifact_sha256=ARTIFACT_SHA256,
            signature=signature,
            view=_StaticProgramView(functions=()),
        )


def test_matcher_snapshots_and_revalidates_both_inputs() -> None:
    matcher = _CapturingMatcher()
    artifact = _artifact()
    signature = _signature()

    matcher.match(artifact, signature)

    captured_artifact, captured_signature = matcher.calls[0]
    assert captured_artifact == artifact
    assert captured_artifact is not artifact
    assert captured_signature == signature
    assert captured_signature is not signature
    captured_artifact.metadata["caller_mutation"] = True
    captured_signature.metadata["caller_mutation"] = True
    assert "caller_mutation" not in artifact.metadata
    assert "caller_mutation" not in signature.metadata


def test_tampered_signature_is_rejected_before_backend_matching() -> None:
    matcher = _CapturingMatcher()
    signature = _signature()
    signature.instruction_sequence[0] = "0xe3a00002"

    with pytest.raises(
        InvalidTriggerMatchingInputError,
        match="detached revalidation",
    ):
        matcher.match(_artifact(), signature)

    assert matcher.calls == []


def test_architecture_mismatch_is_rejected_before_backend_matching() -> None:
    matcher = _CapturingMatcher()

    with pytest.raises(UnsupportedTriggerArtifactError, match="ARM artifacts"):
        matcher.match(_artifact(architecture=Architecture.RISC_V), _signature())

    assert matcher.calls == []


def test_angr_adapter_rejects_non_elf_before_importing_backend() -> None:
    with pytest.raises(UnsupportedTriggerArtifactError, match="ELF"):
        AngrFirmwareTriggerMatcher().match(
            _artifact(artifact_type="raw_binary"),
            _signature(),
        )


def test_angr_adapter_rejects_missing_artifact_path() -> None:
    with pytest.raises(InvalidTriggerMatchingInputError, match="requires.*path"):
        AngrFirmwareTriggerMatcher().match(_artifact(path=None), _signature())


def test_exact_one_block_sequence_matches() -> None:
    result = _result(_one_block_view(WORDS))

    assert len(result.matches) == 1
    assert [
        item.instruction_word
        for item in result.matches[0].instruction_locations
    ] == list(WORDS)


@pytest.mark.parametrize(
    "words",
    [
        (WORDS[1], WORDS[0], WORDS[2]),
        (WORDS[0], "0xe2801002", WORDS[2]),
        (WORDS[0], "0xe1a00000", WORDS[1], WORDS[2]),
        (WORDS[0], "0xe2811001", WORDS[2]),
    ],
)
def test_reordered_changed_inserted_or_different_encoding_does_not_match(
    words: tuple[str, ...],
) -> None:
    assert _result(_one_block_view(words)).matches == []


def test_instruction_locations_preserve_signature_order() -> None:
    match = _result(_one_block_view(WORDS)).matches[0]

    assert [
        item.instruction_address for item in match.instruction_locations
    ] == ["0x00001000", "0x00001004", "0x00001008"]
    assert [
        item.instruction_word for item in match.instruction_locations
    ] == list(WORDS)
    assert match.basic_block_path == ["0x00001000"]


def test_little_endian_decoded_bytes_become_logical_a32_word() -> None:
    assert _logical_a32_word(b"\x01\x00\xa0\xe3", "Iend_LE") == (
        "0xe3a00001"
    )
    assert _logical_a32_word(b"\xe3\xa0\x00\x01", "Iend_BE") == (
        "0xe3a00001"
    )


def test_backend_neutral_view_has_no_raw_data_byte_channel() -> None:
    assert set(_StaticProgramView.__dataclass_fields__) == {
        "functions",
        "diagnostics",
    }
    assert "artifact_bytes" not in _StaticProgramView.__dataclass_fields__
    assert "data_sections" not in _StaticProgramView.__dataclass_fields__


def test_exact_sequence_crosses_valid_same_function_successor() -> None:
    first = _block(
        0x1000,
        WORDS[:2],
        cfg_successors=(0x2000,),
        sequence_successors=(0x2000,),
    )
    second = _block(0x2000, WORDS[2:])

    match = _result(
        _StaticProgramView(functions=(_function((second, first)),))
    ).matches[0]

    assert match.basic_block_path == ["0x00001000", "0x00002000"]
    assert [
        item.basic_block_address for item in match.instruction_locations
    ] == ["0x00001000", "0x00001000", "0x00002000"]


def test_adjacent_or_identical_blocks_without_cfg_successor_do_not_join() -> None:
    first = _block(0x1000, WORDS[:2])
    second = _block(0x1008, WORDS[2:])

    assert _result(
        _StaticProgramView(functions=(_function((first, second)),))
    ).matches == []


def test_cross_function_transition_never_forms_one_match() -> None:
    first = _block(
        0x1000,
        WORDS[:2],
        cfg_successors=(0x2000,),
        sequence_successors=(0x2000,),
    )
    other = _block(
        0x2000,
        WORDS[2:],
        function_address=0x2000,
    )
    view = _StaticProgramView(
        functions=(
            _function((first,)),
            _function((other,), address=0x2000, entry=0x2000, name="other"),
        )
    )

    assert _result(view).matches == []


def test_unreachable_from_function_entry_block_does_not_match() -> None:
    entry = _block(0x1000, ("0xe1a00000",))
    disconnected = _block(0x2000, WORDS)

    assert _result(
        _StaticProgramView(functions=(_function((entry, disconnected)),))
    ).matches == []


def test_loop_matching_is_finite_and_can_consume_only_signature_length() -> None:
    word = "0xe3a00001"
    loop = _block(
        0x1000,
        (word,),
        cfg_successors=(0x1000,),
        sequence_successors=(0x1000,),
    )

    result = _result(
        _StaticProgramView(functions=(_function((loop,)),)),
        signature=_signature((word, word, word)),
    )

    assert len(result.matches) == 1
    assert len(result.matches[0].instruction_locations) == 3


def test_multiple_matching_paths_are_sorted_and_deduplicated() -> None:
    entry = _block(
        0x1000,
        WORDS[:1],
        cfg_successors=(0x2000, 0x3000, 0x2000),
        sequence_successors=(0x3000, 0x2000, 0x2000),
    )
    left = _block(0x2000, WORDS[1:])
    right = _block(0x3000, WORDS[1:])
    view = _StaticProgramView(functions=(_function((right, entry, left)),))

    first = _result(view)
    second = _result(view)

    assert len(first.matches) == 2
    assert first == second
    assert first.model_dump_json() == second.model_dump_json()
    assert [item.basic_block_path[-1] for item in first.matches] == [
        "0x00002000",
        "0x00003000",
    ]


def test_thumb_or_non_a32_block_is_ignored() -> None:
    thumb = _block(0x1000, WORDS, is_a32=False, instruction_size=2)

    result = _result(
        _StaticProgramView(
            functions=(_function((thumb,)),),
            diagnostics=("skipped_non_a32_blocks:1",),
        )
    )

    assert result.matches == []
    assert "skipped_non_a32_blocks:1" in result.diagnostics


def test_non_four_byte_instruction_cannot_enter_a32_match() -> None:
    block = _block(0x1000, WORDS, instruction_size=2)

    assert _result(
        _StaticProgramView(functions=(_function((block,)),))
    ).matches == []


def test_zero_match_result_is_valid_and_not_a_rejection() -> None:
    result = _result(_one_block_view(("0xe1a00000",)))
    serialized = result.model_dump(mode="json")

    assert result.matches == []
    assert "exact_matches:0" in result.diagnostics
    assert "status" not in serialized
    assert "rejected" not in json.dumps(serialized).lower()


def test_match_contract_contains_only_structural_static_facts() -> None:
    match = _result(_one_block_view(WORDS)).matches[0]
    serialized = match.model_dump(mode="json")

    assert serialized["artifact_id"] == _artifact().id
    assert serialized["artifact_sha256"] == ARTIFACT_SHA256
    assert serialized["signature_id"] == _signature().id
    assert serialized["function_address"] == "0x00001000"
    for forbidden in (
        "triggerable",
        "verified",
        "vulnerability_status",
        "chain_status",
        "score",
        "confidence",
        "dynamic_observation",
        "runtime_trace",
        "preconditions_satisfied",
        "hardware_failure_reproduced",
        "path",
    ):
        assert forbidden not in serialized


def test_match_id_is_deterministic_and_rejects_tampering() -> None:
    first = _result(_one_block_view(WORDS)).matches[0]
    second = _result(_one_block_view(WORDS)).matches[0]
    payload = first.model_dump(mode="json")
    payload["instruction_locations"][0]["instruction_address"] = "0x00001004"

    assert first.id == second.id
    with pytest.raises(ValidationError, match="ID is not deterministic"):
        StaticFirmwareTriggerMatch.model_validate(payload)


def test_match_metadata_does_not_change_semantic_id() -> None:
    match = _result(_one_block_view(WORDS)).matches[0]
    payload = match.model_dump(mode="json")

    first = StaticFirmwareTriggerMatch.create(
        **{
            **{key: value for key, value in payload.items() if key not in {"id", "metadata"}},
            "metadata": {"note": "first"},
        }
    )
    second = StaticFirmwareTriggerMatch.create(
        **{
            **{key: value for key, value in payload.items() if key not in {"id", "metadata"}},
            "metadata": {"note": "second"},
        }
    )

    assert first.id == second.id
    assert first.metadata != second.metadata


def test_artifact_content_hash_change_alters_match_identity() -> None:
    first = _result(_one_block_view(WORDS), artifact_sha256="a" * 64)
    second = _result(_one_block_view(WORDS), artifact_sha256="b" * 64)

    assert first.matches[0].id != second.matches[0].id


def test_signature_change_alters_match_identity() -> None:
    first = _result(_one_block_view(WORDS)).matches[0]
    changed_signature = _signature((WORDS[0], WORDS[1]))
    second = _result(
        _one_block_view(WORDS[:2]),
        signature=changed_signature,
    ).matches[0]

    assert first.signature_id != second.signature_id
    assert first.id != second.id


def test_public_match_result_never_serializes_host_path() -> None:
    serialized = _result(_one_block_view(WORDS)).model_dump_json()

    assert str(SIGNATURE_PATH.resolve()) not in serialized
    assert "artifact_path" not in serialized
    assert '"path"' not in serialized


def test_match_result_round_trip_and_repeat_run_are_equivalent() -> None:
    first = _result(_one_block_view(WORDS))
    restored = StaticFirmwareTriggerMatchResult.model_validate_json(
        first.model_dump_json()
    )

    assert restored == first
    assert restored.model_dump_json() == first.model_dump_json()


def test_signature_preconditions_remain_reference_only_and_unevaluated() -> None:
    match = _result(_one_block_view(WORDS)).matches[0]
    serialized = match.model_dump(mode="json")

    assert match.signature_id == _signature().id
    assert "preconditions" not in serialized
    assert "register_preconditions" not in serialized
    assert "memory_preconditions" not in serialized
    assert "privilege_mode" not in serialized
    assert "preconditions_satisfied" not in serialized


def test_unknown_result_fields_fail_closed() -> None:
    payload = _result(_one_block_view(WORDS)).model_dump(mode="json")
    payload["verified"] = True

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        StaticFirmwareTriggerMatchResult.model_validate(payload)
