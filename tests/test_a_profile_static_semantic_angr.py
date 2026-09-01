"""Real angr acceptance for the owned AArch64 semantic fixture."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from chipchain.analysis import ProgramArtifact
from chipchain.hardware_trigger import (
    A_PROFILE_STATIC_RECOGNITION_PROFILE_PARTIAL_V1,
    AProfileSemanticEventKind,
    AProfileStaticSemanticExtractionPlan,
    AProfileStaticSemanticExtractionResult,
    AProfileSystemRegister,
    AngrAProfileStaticSemanticExtractor,
    ArmExecutionMode,
    HardwareTriggerSignature,
    InvalidAProfileStaticSemanticInputError,
    RemainingObjectiveObligation,
    StaticEffectiveMemoryTypeResolution,
    UnsupportedAProfileStaticSemanticArtifactError,
)
from chipchain.hardware_trigger.a_profile_static_semantic_angr import (
    _AUDITED_LOAD_INSTRUCTION_IDS,
    _AUDITED_STORE_EXCLUSIVE_INSTRUCTION_IDS,
    _DecodedA64Instruction,
    _DecodedA64Operand,
    _classify_decoded_a64_instruction,
    _logical_a64_word,
    _normalize_decoded_a64_instruction,
    _recognition_profile,
)
from chipchain.models import Architecture


angr = pytest.importorskip("angr")
capstone = pytest.importorskip("capstone")
from capstone import arm64  # noqa: E402


pytestmark = pytest.mark.angr

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = (
    ROOT
    / "tests/fixtures/phase10d/a_profile_static_semantic_a64/"
    "a_profile_static_semantic_a64.elf"
)
FIXTURE_DIRECTORY = FIXTURE.parent
EXPECTED_PATH = FIXTURE_DIRECTORY / "expected_static_semantics.json"
PLAN_PATH = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_a_profile_static_semantic_extraction_plan_v1.json"
)
ARM32_FIXTURE = (
    ROOT
    / "tests/fixtures/phase9c/arm_a32_trigger_match/"
    "arm_a32_trigger_match.elf"
)
ARM32_SIGNATURE = (
    ROOT
    / "tests/fixtures/phase9c/arm_a32_trigger_runtime/"
    "hardware_trigger_signature.json"
)
EXPECTED_FIXTURE_SHA256 = (
    "eacca62d264164cfb8970fd09d0df9c7bc548fbe04f7ee505001c9b594087c69"
)
EXPECTED_PLAN_ID = (
    "a-profile-static-semantic-extraction-plan:"
    "2efffa2cb11cb1fd9983a16341a9b0cb05c08ad9736a4c86c9cd74997ba79d76"
)
EXPECTED_A32_SIGNATURE_ID = (
    "hardware-trigger-signature:"
    "6c40f20a04baf56570c4f2994f1859e4b4012371300c78b43143829d16bd26ba"
)


@pytest.fixture(scope="module")
def expected() -> dict[str, object]:
    return json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def plan() -> AProfileStaticSemanticExtractionPlan:
    value = AProfileStaticSemanticExtractionPlan.model_validate_json(
        PLAN_PATH.read_bytes()
    )
    assert value.id == EXPECTED_PLAN_ID
    return value


@pytest.fixture(scope="module")
def artifact() -> ProgramArtifact:
    return _artifact()


@pytest.fixture(scope="module")
def result(
    artifact: ProgramArtifact,
    plan: AProfileStaticSemanticExtractionPlan,
) -> AProfileStaticSemanticExtractionResult:
    return AngrAProfileStaticSemanticExtractor().extract(artifact, plan)


def _artifact(
    *,
    path: Path | None = FIXTURE,
    architecture: Architecture = Architecture.ARM,
    artifact_type: str = "elf",
) -> ProgramArtifact:
    return ProgramArtifact(
        id="owned-synthetic-a64-static-semantic-fixture",
        architecture=architecture,
        artifact_type=artifact_type,
        path=None if path is None else str(path),
        fixture_identifier="phase10d-a-profile-static-semantic-a64",
        metadata={"owned": True, "synthetic": True, "fixture": True},
    )


def _decode(word: int):
    decoder = capstone.Cs(
        capstone.CS_ARCH_ARM64,
        capstone.CS_MODE_LITTLE_ENDIAN,
    )
    decoder.detail = True
    instruction = next(
        decoder.disasm(word.to_bytes(4, byteorder="little"), 0x400000)
    )
    return _normalize_decoded_a64_instruction(instruction, arm64=arm64)


def _facts_by_kind(result: AProfileStaticSemanticExtractionResult):
    return {item.event_kind: item for item in result.instruction_facts}


def test_fixture_hash_layout_and_classification_are_auditable(
    expected: dict[str, object],
) -> None:
    digest, filename = (FIXTURE_DIRECTORY / "SHA256SUMS").read_text(
        encoding="ascii"
    ).split()
    classification = expected["fixture_classification"]

    assert filename == FIXTURE.name
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == digest
    assert digest == expected["artifact_sha256"] == EXPECTED_FIXTURE_SHA256
    assert classification == {
        "owned": True,
        "synthetic": True,
        "real_vulnerability": False,
        "affected_hardware_reproduction": False,
        "triggerability_demonstration": False,
    }
    assert not (FIXTURE_DIRECTORY / "ground_truth.json").exists()


def test_fixture_generator_is_byte_deterministic(
    expected: dict[str, object],
) -> None:
    namespace = runpy.run_path(str(FIXTURE_DIRECTORY / "generate_fixture.py"))
    generated_bytes, generated_expected = namespace["build_elf"]()
    committed_without_hash = dict(expected)
    committed_without_hash.pop("artifact_sha256")

    assert generated_bytes == FIXTURE.read_bytes()
    assert generated_expected == committed_without_hash


def test_loaded_fixture_is_actual_aarch64_64_bit() -> None:
    project = angr.Project(str(FIXTURE), auto_load_libs=False)

    assert project.arch.name == "AARCH64"
    assert project.arch.bits == 64
    assert project.loader.main_object.binary == str(FIXTURE)


def test_exact_artifact_plan_and_result_bindings(
    artifact: ProgramArtifact,
    plan: AProfileStaticSemanticExtractionPlan,
    result: AProfileStaticSemanticExtractionResult,
) -> None:
    assert result.artifact_id == artifact.id
    assert result.artifact_sha256 == EXPECTED_FIXTURE_SHA256
    assert result.extraction_plan_id == plan.id
    assert result.extraction_plan_snapshot == plan
    assert result.source_pattern_id == plan.source_pattern_id


def test_exact_three_semantic_facts_match_fixture_expectations(
    result: AProfileStaticSemanticExtractionResult,
    expected: dict[str, object],
) -> None:
    actual = [
        {
            "function": item.function_name,
            "function_address": item.function_address,
            "instruction_address": item.instruction_address,
            "instruction_word": item.instruction_word,
            "event_kind": item.event_kind.value,
            "system_register": (
                None if item.system_register is None else item.system_register.value
            ),
            "memory_type_resolution": item.memory_type_resolution.value,
        }
        for item in result.instruction_facts
    ]

    assert actual == expected["expected_facts"]
    assert len(actual) == expected["expected_fact_count"] == 3


def test_fact_address_word_size_and_static_only_shape(
    result: AProfileStaticSemanticExtractionResult,
) -> None:
    for fact in result.instruction_facts:
        assert len(fact.instruction_address) == 18
        assert len(fact.basic_block_address) == 18
        assert len(fact.function_address) == 18
        assert len(fact.instruction_word) == 10
        assert fact.instruction_size == 4
    fields = type(result.instruction_facts[0]).model_fields
    assert "effective_memory_type" not in fields
    assert "executed" not in fields
    assert "runtime_el" not in fields


def test_load_fact_remains_effective_memory_type_unresolved(
    result: AProfileStaticSemanticExtractionResult,
) -> None:
    load = _facts_by_kind(result)[AProfileSemanticEventKind.MEMORY_LOAD]

    assert load.system_register is None
    assert load.memory_type_resolution is (
        StaticEffectiveMemoryTypeResolution.REQUIRES_OBJECTIVE_TRANSLATION_CONTEXT
    )


def test_load_fact_binds_both_load_predicates_without_fact_duplication(
    result: AProfileStaticSemanticExtractionResult,
) -> None:
    load = _facts_by_kind(result)[AProfileSemanticEventKind.MEMORY_LOAD]
    candidates = [
        item
        for item in result.predicate_candidates
        if item.static_instruction_fact_id == load.id
    ]

    assert [(item.case_id, item.position_index) for item in candidates] == [
        ("case_a", 2),
        ("case_b", 1),
    ]
    assert {item.static_instruction_fact_id for item in candidates} == {load.id}
    constraints = {
        item.case_id: [
            value.value
            for value in item.predicate_entry_snapshot.required_memory_type_constraints
        ]
        for item in candidates
    }
    assert constraints == {
        "case_a": ["device", "normal_non_cacheable"],
        "case_b": ["device"],
    }
    assert all(
        RemainingObjectiveObligation.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
        in item.remaining_objective_obligations
        for item in candidates
    )


def test_par_fact_candidates_retain_runtime_context_obligation(
    result: AProfileStaticSemanticExtractionResult,
) -> None:
    fact = _facts_by_kind(result)[
        AProfileSemanticEventKind.SYSTEM_REGISTER_READ
    ]
    candidates = [
        item
        for item in result.predicate_candidates
        if item.static_instruction_fact_id == fact.id
    ]

    assert fact.system_register is AProfileSystemRegister.PAR_EL1
    assert {(item.case_id, item.position_index) for item in candidates} == {
        ("case_a", 1),
        ("case_b", 2),
    }
    assert all(
        RemainingObjectiveObligation.RUNTIME_EXECUTION_CONTEXT_REQUIRED
        in item.remaining_objective_obligations
        for item in candidates
    )


def test_store_exclusive_candidates_retain_universal_obligations(
    result: AProfileStaticSemanticExtractionResult,
) -> None:
    fact = _facts_by_kind(result)[AProfileSemanticEventKind.STORE_EXCLUSIVE]
    candidates = [
        item
        for item in result.predicate_candidates
        if item.static_instruction_fact_id == fact.id
    ]
    required = {
        RemainingObjectiveObligation.RUNTIME_EXECUTION_REQUIRED,
        RemainingObjectiveObligation.RELATION_PROXIMITY_REMAINS_UNRESOLVED,
        RemainingObjectiveObligation.ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED,
    }

    assert {(item.case_id, item.position_index) for item in candidates} == {
        ("case_a", 1),
        ("case_b", 2),
    }
    assert all(
        required.issubset(item.remaining_objective_obligations)
        for item in candidates
    )
    assert all(
        RemainingObjectiveObligation.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
        not in item.remaining_objective_obligations
        for item in candidates
    )


def test_every_candidate_snapshot_is_the_exact_plan_entry(
    result: AProfileStaticSemanticExtractionResult,
) -> None:
    entries = {
        item.predicate_ref: item
        for item in result.extraction_plan_snapshot.predicate_entries
    }

    assert len(result.predicate_candidates) == 6
    assert all(
        item.predicate_entry_snapshot == entries[item.predicate_ref]
        for item in result.predicate_candidates
    )


def test_diagnostics_are_partial_profile_and_outcome_neutral(
    result: AProfileStaticSemanticExtractionResult,
) -> None:
    assert result.diagnostic_codes == [
        "decoded_instruction_count:12",
        "deduplicated_semantic_fact_count:0",
        "predicate_candidate_count:6",
        "semantic_fact_count:3",
        "skipped_non_executable_block_count:0",
        (
            "static_recognition_profile:"
            f"{A_PROFILE_STATIC_RECOGNITION_PROFILE_PARTIAL_V1}"
        ),
        "unsupported_semantic_instruction_count:9",
    ]
    forbidden = ("vulnerability", "triggered", "satisfied", "verified")
    assert all(
        fragment not in diagnostic
        for diagnostic in result.diagnostic_codes
        for fragment in forbidden
    )


def test_non_executable_exact_byte_copies_are_ignored(
    result: AProfileStaticSemanticExtractionResult,
) -> None:
    binary = FIXTURE.read_bytes()
    positive_words = (0xF9400020, 0xC8007C41, 0xD5387400)

    assert all(binary.count(word.to_bytes(4, "little")) == 2 for word in positive_words)
    assert all(
        int(item.instruction_address, 16) < 0x401000
        for item in result.instruction_facts
    )
    assert {item.function_name for item in result.instruction_facts} == {
        "owned_load_example",
        "owned_store_exclusive_example",
        "owned_par_el1_read_example",
    }


@pytest.mark.parametrize(
    "word",
    [
        0xF9000020,  # STR
        0xC85F7C41,  # LDXR
        0xD5187400,  # MSR PAR_EL1
        0xD5386000,  # MRS FAR_EL1
        0xF8400020,  # unsupported LDUR
        0xC89FFC20,  # STLR, but not store-exclusive
    ],
)
def test_near_miss_decoder_id_and_operands_do_not_classify(word: int) -> None:
    profile = _recognition_profile(arm64)

    assert _classify_decoded_a64_instruction(
        _decode(word),
        profile=profile,
    ) is None


def test_exact_closed_recognition_profile_uses_ids_and_operand_shapes() -> None:
    profile = _recognition_profile(arm64)

    assert _AUDITED_LOAD_INSTRUCTION_IDS == ("ARM64_INS_LDR",)
    assert _AUDITED_STORE_EXCLUSIVE_INSTRUCTION_IDS == (
        "ARM64_INS_STXR",
        "ARM64_INS_STXRB",
        "ARM64_INS_STXRH",
        "ARM64_INS_STLXR",
        "ARM64_INS_STLXRB",
        "ARM64_INS_STLXRH",
    )
    assert _classify_decoded_a64_instruction(
        _decode(0xF9400020), profile=profile
    ).event_kind is AProfileSemanticEventKind.MEMORY_LOAD
    assert _classify_decoded_a64_instruction(
        _decode(0xC8007C41), profile=profile
    ).event_kind is AProfileSemanticEventKind.STORE_EXCLUSIVE
    par = _classify_decoded_a64_instruction(
        _decode(0xD5387400), profile=profile
    )
    assert par.event_kind is AProfileSemanticEventKind.SYSTEM_REGISTER_READ
    assert par.system_register is AProfileSystemRegister.PAR_EL1


def test_every_audited_store_exclusive_id_requires_exact_operand_shape() -> None:
    profile = _recognition_profile(arm64)
    valid_operands = (
        _DecodedA64Operand(kind=profile.register_operand_kind),
        _DecodedA64Operand(kind=profile.register_operand_kind),
        _DecodedA64Operand(kind=profile.memory_operand_kind),
    )
    invalid_operands = (
        _DecodedA64Operand(kind=profile.register_operand_kind),
        _DecodedA64Operand(kind=profile.memory_operand_kind),
    )

    assert len(profile.store_exclusive_instruction_ids) == 6
    for instruction_id in sorted(profile.store_exclusive_instruction_ids):
        valid = _DecodedA64Instruction(
            address=0x400000,
            instruction_id=instruction_id,
            raw_bytes=b"\x00\x00\x00\x00",
            size=4,
            operands=valid_operands,
        )
        invalid = _DecodedA64Instruction(
            address=0x400000,
            instruction_id=instruction_id,
            raw_bytes=b"\x00\x00\x00\x00",
            size=4,
            operands=invalid_operands,
        )

        recognized = _classify_decoded_a64_instruction(valid, profile=profile)
        assert recognized is not None
        assert recognized.event_kind is AProfileSemanticEventKind.STORE_EXCLUSIVE
        assert _classify_decoded_a64_instruction(invalid, profile=profile) is None


def test_main_object_function_filter_excludes_external_simprocedure_and_plt() -> None:
    main_object = SimpleNamespace(contains_addr=lambda address: address < 0x500000)
    extractor = AngrAProfileStaticSemanticExtractor()

    assert extractor._is_main_object_function(  # noqa: SLF001
        SimpleNamespace(addr=0x400000, is_simprocedure=False, is_plt=False),
        main_object,
    )
    assert not extractor._is_main_object_function(  # noqa: SLF001
        SimpleNamespace(addr=0x600000, is_simprocedure=False, is_plt=False),
        main_object,
    )
    assert not extractor._is_main_object_function(  # noqa: SLF001
        SimpleNamespace(addr=0x400000, is_simprocedure=True, is_plt=False),
        main_object,
    )
    assert not extractor._is_main_object_function(  # noqa: SLF001
        SimpleNamespace(addr=0x400000, is_simprocedure=False, is_plt=True),
        main_object,
    )


def test_a64_logical_word_requires_exactly_four_decoder_bytes() -> None:
    assert (
        _logical_a64_word(b"\x20\x00\x40\xf9", "Iend_LE", 4)
        == "0xf9400020"
    )
    with pytest.raises(ValueError, match="size"):
        _logical_a64_word(b"\x20\x00\x40\xf9", "Iend_LE", 8)
    with pytest.raises(ValueError, match="exactly four"):
        _logical_a64_word(b"\x20\x00", "Iend_LE", 4)
    with pytest.raises(ValueError, match="endianness"):
        _logical_a64_word(b"\x20\x00\x40\xf9", "unknown", 4)


def test_arm32_elf_is_rejected_by_new_extractor(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    with pytest.raises(
        UnsupportedAProfileStaticSemanticArtifactError,
        match="not AArch64",
    ):
        AngrAProfileStaticSemanticExtractor().extract(
            _artifact(path=ARM32_FIXTURE),
            plan,
        )


def test_x86_64_elf_is_rejected_by_loaded_architecture(
    tmp_path: Path,
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    x86_64_elf = tmp_path / "owned-wrong-architecture.elf"
    header_changed = bytearray(FIXTURE.read_bytes())
    header_changed[18:20] = (62).to_bytes(2, byteorder="little")  # EM_X86_64
    x86_64_elf.write_bytes(header_changed)

    with pytest.raises(
        UnsupportedAProfileStaticSemanticArtifactError,
        match="not AArch64",
    ):
        AngrAProfileStaticSemanticExtractor().extract(
            _artifact(path=x86_64_elf),
            plan,
        )


def test_malformed_non_elf_is_rejected(
    tmp_path: Path,
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    malformed = tmp_path / "owned-malformed.elf"
    malformed.write_bytes(b"owned synthetic non-ELF")

    with pytest.raises(InvalidAProfileStaticSemanticInputError, match="could not load"):
        AngrAProfileStaticSemanticExtractor().extract(
            _artifact(path=malformed),
            plan,
        )


def test_wrong_artifact_type_architecture_and_missing_path_are_rejected(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    extractor = AngrAProfileStaticSemanticExtractor()
    with pytest.raises(UnsupportedAProfileStaticSemanticArtifactError):
        extractor.extract(_artifact(artifact_type="raw"), plan)
    with pytest.raises(UnsupportedAProfileStaticSemanticArtifactError):
        extractor.extract(_artifact(architecture=Architecture.RISC_V), plan)
    with pytest.raises(InvalidAProfileStaticSemanticInputError, match="path"):
        extractor.extract(_artifact(path=None), plan)


def test_mutated_plan_object_is_detached_and_rejected(
    artifact: ProgramArtifact,
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    changed = plan.model_copy(deep=True)
    object.__setattr__(
        changed,
        "id",
        "a-profile-static-semantic-extraction-plan:" + "0" * 64,
    )

    with pytest.raises(InvalidAProfileStaticSemanticInputError, match="detached"):
        AngrAProfileStaticSemanticExtractor().extract(artifact, changed)


def test_artifact_integrity_drift_fails_closed_before_result(
    monkeypatch: pytest.MonkeyPatch,
    artifact: ProgramArtifact,
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    extractor = AngrAProfileStaticSemanticExtractor()
    exact = FIXTURE.read_bytes()
    reads = iter((exact, exact + b"changed"))
    monkeypatch.setattr(extractor, "_read_artifact_bytes", lambda path: next(reads))

    with pytest.raises(InvalidAProfileStaticSemanticInputError, match="changed"):
        extractor.extract(artifact, plan)


def test_repeated_extraction_is_byte_deterministic(
    artifact: ProgramArtifact,
    plan: AProfileStaticSemanticExtractionPlan,
    result: AProfileStaticSemanticExtractionResult,
) -> None:
    repeated = AngrAProfileStaticSemanticExtractor().extract(artifact, plan)

    assert repeated == result
    assert repeated.id == result.id
    assert repeated.model_dump_json() == result.model_dump_json()


def test_result_has_no_case_order_proximity_or_verdict_surface(
    result: AProfileStaticSemanticExtractionResult,
) -> None:
    forbidden = {
        "case_candidates",
        "program_order_satisfied",
        "proximity_satisfied",
        "triggerability",
        "feasibility",
        "verification",
    }
    assert forbidden.isdisjoint(type(result).model_fields)
    assert not any("case_candidate" in item for item in result.diagnostic_codes)


def test_new_production_module_import_firewall() -> None:
    path = (
        ROOT
        / "src/chipchain/hardware_trigger/a_profile_static_semantic_angr.py"
    )
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    forbidden = (
        "TriggerabilityStatus",
        "TriggerabilityAggregationResult",
        "ChainFeasibilityStatus",
        "ChainFeasibilityAssessment",
        "VerificationRecord",
        "GroundTruth",
        "ReasoningProvider",
        "Evidence",
        "chipchain.runtime",
        "chipchain.qemu",
    )

    assert all(item not in text for item in forbidden)
    assert not any(
        isinstance(node, (ast.Import, ast.ImportFrom))
        and "network" in ast.unparse(node).lower()
        for node in ast.walk(tree)
    )


def test_old_a32_contract_identity_remains_unchanged() -> None:
    signature = HardwareTriggerSignature.model_validate_json(
        ARM32_SIGNATURE.read_bytes()
    )

    assert [item.value for item in ArmExecutionMode] == ["arm_a32"]
    assert signature.id == EXPECTED_A32_SIGNATURE_ID
