"""Optional owned-ELF integration for Phase 9C Step 2 angr matching."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from chipchain.analysis import ProgramArtifact
from chipchain.hardware_trigger import (
    AngrFirmwareTriggerMatcher,
    HardwareTriggerSignature,
    StaticFirmwareTriggerMatchResult,
)
from chipchain.models import Architecture


angr = pytest.importorskip("angr")
pytestmark = pytest.mark.angr

FIXTURE_DIRECTORY = (
    Path(__file__).parent / "fixtures" / "phase9c" / "arm_a32_trigger_match"
)
ELF_PATH = FIXTURE_DIRECTORY / "arm_a32_trigger_match.elf"
SIGNATURE_PATH = (
    FIXTURE_DIRECTORY.parent / "arm_a32_hardware_trigger_signature.json"
)


@pytest.fixture(scope="module")
def ground_truth() -> dict[str, object]:
    return json.loads(
        (FIXTURE_DIRECTORY / "ground_truth.json").read_text(encoding="utf-8")
    )


@pytest.fixture(scope="module")
def artifact() -> ProgramArtifact:
    return ProgramArtifact(
        id="synthetic-owned-arm-a32-trigger-match-elf",
        architecture=Architecture.ARM,
        artifact_type="elf",
        path=str(ELF_PATH),
        fixture_identifier="synthetic-owned-phase9c-step2-elf",
        metadata={"fixture": True, "synthetic": True, "owned": True},
    )


@pytest.fixture(scope="module")
def signature() -> HardwareTriggerSignature:
    return HardwareTriggerSignature.model_validate_json(
        SIGNATURE_PATH.read_text(encoding="utf-8")
    )


def _changed_signature(
    source: HardwareTriggerSignature,
    words: list[str],
) -> HardwareTriggerSignature:
    return HardwareTriggerSignature.create(
        architecture=source.architecture,
        execution_mode=source.execution_mode,
        hardware_vulnerability_id=source.hardware_vulnerability_id,
        instruction_sequence=words,
        preconditions=source.preconditions,
        expected_effect=source.expected_effect,
        proof=source.proof,
        metadata=source.metadata,
    )


def test_owned_elf_hash_layout_and_non_executable_copy_are_auditable(
    ground_truth: dict[str, object],
) -> None:
    expected_digest, expected_name = (FIXTURE_DIRECTORY / "SHA256SUMS").read_text(
        encoding="ascii"
    ).split()
    binary = ELF_PATH.read_bytes()
    trigger_words = ground_truth["expected_match"]["instruction_words"]
    raw_little_endian_pattern = b"".join(
        struct.pack("<I", int(word, 16)) for word in trigger_words
    )
    project = angr.Project(str(ELF_PATH), auto_load_libs=False)
    data_section = project.loader.main_object.sections_map[".data"]

    assert expected_name == ELF_PATH.name
    assert hashlib.sha256(binary).hexdigest() == expected_digest
    assert ground_truth["artifact_sha256"] == expected_digest
    assert ground_truth["fixture_type"] == "owned_synthetic"
    assert ground_truth["real_hardware_vulnerability"] is False
    assert binary.count(raw_little_endian_pattern) == 2
    assert data_section.is_executable is False


def test_angr_matcher_finds_exact_ground_truth_occurrence_only(
    artifact: ProgramArtifact,
    signature: HardwareTriggerSignature,
    ground_truth: dict[str, object],
) -> None:
    result = AngrFirmwareTriggerMatcher().match(artifact, signature)
    expected = ground_truth["expected_match"]

    assert isinstance(result, StaticFirmwareTriggerMatchResult)
    assert result.artifact_sha256 == ground_truth["artifact_sha256"]
    assert result.signature_id == ground_truth["signature_id"]
    assert len(result.matches) == 1
    match = result.matches[0]
    assert match.function_name == expected["function"]
    assert match.function_address == expected["function_address"]
    assert [
        item.instruction_address for item in match.instruction_locations
    ] == expected["instruction_addresses"]
    assert [
        item.instruction_word for item in match.instruction_locations
    ] == expected["instruction_words"]
    assert match.basic_block_path == expected["basic_block_path"]


def test_real_owned_elf_matching_is_byte_deterministic(
    artifact: ProgramArtifact,
    signature: HardwareTriggerSignature,
) -> None:
    first = AngrFirmwareTriggerMatcher().match(artifact, signature)
    second = AngrFirmwareTriggerMatcher().match(artifact, signature)

    assert second == first
    assert second.model_dump_json() == first.model_dump_json()


@pytest.mark.parametrize("change", ["word", "order"])
def test_near_miss_or_reordered_signature_has_zero_exact_matches(
    change: str,
    artifact: ProgramArtifact,
    signature: HardwareTriggerSignature,
) -> None:
    words = list(signature.instruction_sequence)
    if change == "word":
        words[1] = "0xe2801003"
    else:
        words[1], words[2] = words[2], words[1]
    changed = _changed_signature(signature, words)

    result = AngrFirmwareTriggerMatcher().match(artifact, changed)

    assert result.matches == []
    assert "exact_matches:0" in result.diagnostics
