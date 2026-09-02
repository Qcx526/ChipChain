"""Real angr tests for the plan-independent AArch64 semantic decoder."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest

from chipchain.analysis import (
    AARCH64_STATIC_SEMANTIC_DECODER_PROFILE_AUDITED_PARTIAL_V1,
    AArch64StaticSemanticBackendError,
    AngrAArch64StaticSemanticDecoder,
    InvalidAnalysisInputError,
    ProgramArtifact,
    StaticSemanticAttributeName,
    StaticSemanticInventory,
    StaticSemanticInventoryScope,
    StaticSemanticOperation,
    UnsupportedArtifactError,
)
from chipchain.analysis import aarch64_static_semantic_decoder as decoder_module
from chipchain.analysis.aarch64_static_semantic_decoder import (
    _AUDITED_LOAD_EXCLUSIVE_IDS,
    _AUDITED_MEMORY_LOAD_IDS,
    _AUDITED_MEMORY_STORE_IDS,
    _AUDITED_STORE_EXCLUSIVE_IDS,
    _DecodedAArch64Instruction,
    _DecodedAArch64Operand,
    _classify_instruction,
    _decoder_profile,
    _normalize_decoded_instruction,
)
from chipchain.models import Architecture


angr = pytest.importorskip("angr")
capstone = pytest.importorskip("capstone")
from capstone import arm64  # noqa: E402


pytestmark = pytest.mark.angr

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIRECTORY = (
    ROOT
    / "tests/fixtures/phase10d/aarch64_generic_static_semantic_v1"
)
FIXTURE = FIXTURE_DIRECTORY / "aarch64_generic_static_semantic_v1.elf"
EXPECTED_PATH = FIXTURE_DIRECTORY / "expected_static_semantics.json"
OLD_FIXTURE = (
    ROOT
    / "tests/fixtures/phase10d/a_profile_static_semantic_a64/"
    "a_profile_static_semantic_a64.elf"
)
ARM32_FIXTURE = (
    ROOT
    / "tests/fixtures/phase9c/arm_a32_trigger_match/"
    "arm_a32_trigger_match.elf"
)
EXPECTED_FIXTURE_SHA256 = (
    "854db6b28d22363a7943ea53bea83e18b25bb38d1dc6d25d99140e61a5374c0b"
)
EXPECTED_INVENTORY_ID = (
    "static-semantic-inventory:"
    "234bffafb5a7fee63f1385a3c31cea5965766f5870935ce36fe82d7912a43db3"
)


def _artifact(
    *,
    path: Path | None = FIXTURE,
    architecture: Architecture = Architecture.ARM,
    artifact_type: str = "elf",
) -> ProgramArtifact:
    return ProgramArtifact(
        id="owned-synthetic-generic-aarch64-v1",
        architecture=architecture,
        artifact_type=artifact_type,
        path=None if path is None else str(path),
        fixture_identifier="phase10d-aarch64-generic-static-semantic-v1",
        metadata={"owned": True, "synthetic": True, "fixture": True},
    )


@pytest.fixture(scope="module")
def expected() -> dict[str, object]:
    return json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def inventory() -> StaticSemanticInventory:
    return AngrAArch64StaticSemanticDecoder().decode(_artifact())


@pytest.fixture(scope="module")
def old_inventory() -> StaticSemanticInventory:
    return AngrAArch64StaticSemanticDecoder().decode(
        _artifact(path=OLD_FIXTURE)
    )


def _attributes(fact) -> dict[str, str]:
    return {item.name.value: item.value for item in fact.attributes}


def _decode(word: int) -> _DecodedAArch64Instruction:
    engine = capstone.Cs(
        capstone.CS_ARCH_ARM64,
        capstone.CS_MODE_LITTLE_ENDIAN,
    )
    engine.detail = True
    instruction = next(
        engine.disasm(word.to_bytes(4, byteorder="little"), 0x400000)
    )
    return _normalize_decoded_instruction(instruction, arm64=arm64)


def _overlap_decode_inputs(
    fallback_word: int,
) -> tuple[SimpleNamespace, SimpleNamespace]:
    engine = capstone.Cs(
        capstone.CS_ARCH_ARM64,
        capstone.CS_MODE_LITTLE_ENDIAN,
    )
    engine.detail = True
    cfg_instruction = next(
        engine.disasm((0xF9400020).to_bytes(4, "little"), 0x400004)
    )
    executable_section = SimpleNamespace(is_executable=True)
    main_object = SimpleNamespace(
        symbols=[
            SimpleNamespace(
                is_function=True,
                name="owned_cfg_function",
                rebased_addr=0x400000,
                size=8,
            ),
            SimpleNamespace(
                is_function=True,
                name="owned_overlapping_fallback",
                rebased_addr=0x400004,
                size=4,
            ),
        ],
        contains_addr=lambda address: 0x400000 <= address < 0x401000,
        find_section_containing=lambda _address: executable_section,
        find_segment_containing=lambda _address: None,
    )
    block = SimpleNamespace(
        addr=0x400000,
        size=8,
        capstone=SimpleNamespace(insns=[cfg_instruction]),
    )
    function = SimpleNamespace(
        addr=0x400000,
        is_simprocedure=False,
        is_plt=False,
        block_addrs_set={0x400000},
    )
    project = SimpleNamespace(
        loader=SimpleNamespace(
            main_object=main_object,
            memory=SimpleNamespace(
                load=lambda _address, _size: fallback_word.to_bytes(
                    4, "little"
                )
            ),
        ),
        factory=SimpleNamespace(block=lambda _address: block),
        arch=SimpleNamespace(capstone=engine),
    )
    cfg = SimpleNamespace(
        kb=SimpleNamespace(functions={function.addr: function})
    )
    return project, cfg


def test_final_api_accepts_only_one_program_artifact() -> None:
    signature = inspect.signature(AngrAArch64StaticSemanticDecoder.decode)

    assert list(signature.parameters) == ["self", "artifact"]
    assert signature.parameters["artifact"].annotation == "ProgramArtifact"
    assert signature.return_annotation == "StaticSemanticInventory"
    forbidden = ("plan", "cve", "pattern", "predicate", "candidate")
    assert all(value not in signature.parameters for value in forbidden)


def test_profile_and_inventory_contract_are_exact(
    inventory: StaticSemanticInventory,
) -> None:
    assert AARCH64_STATIC_SEMANTIC_DECODER_PROFILE_AUDITED_PARTIAL_V1 == (
        "phase10d_aarch64_static_semantic_decoder_audited_partial_v1"
    )
    assert type(inventory) is StaticSemanticInventory
    assert inventory.architecture is Architecture.ARM
    assert inventory.instruction_set == "aarch64"
    assert inventory.decoder_profile_id == (
        AARCH64_STATIC_SEMANTIC_DECODER_PROFILE_AUDITED_PARTIAL_V1
    )
    assert inventory.analysis_scope is (
        StaticSemanticInventoryScope
        .PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY
    )
    assert inventory.id == EXPECTED_INVENTORY_ID


def test_fixture_is_byte_deterministic_and_auditable(
    expected: dict[str, object],
) -> None:
    digest, filename = (FIXTURE_DIRECTORY / "SHA256SUMS").read_text(
        encoding="ascii"
    ).split()
    namespace = runpy.run_path(str(FIXTURE_DIRECTORY / "generate_fixture.py"))
    generated, generated_expected = namespace["build_elf"]()
    expected_without_hash = dict(expected)
    expected_without_hash.pop("artifact_sha256")

    assert filename == FIXTURE.name
    assert digest == EXPECTED_FIXTURE_SHA256
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == digest
    assert generated == FIXTURE.read_bytes()
    assert generated_expected == expected_without_hash
    assert expected["fixture_classification"] == {
        "owned": True,
        "synthetic": True,
        "real_vulnerability": False,
        "affected_hardware_reproduction": False,
        "runtime_execution_evidence": False,
        "triggerability_demonstration": False,
    }
    assert not (FIXTURE_DIRECTORY / "ground_truth.json").exists()


def test_real_fixture_matches_all_expected_semantic_facts(
    inventory: StaticSemanticInventory,
    expected: dict[str, object],
) -> None:
    actual = [
        {
            "function": fact.function_name,
            "function_address": fact.function_address,
            "basic_block_address": fact.basic_block_address,
            "instruction_address": fact.instruction_address,
            "instruction_bytes": fact.instruction_bytes,
            "instruction_size": fact.instruction_size,
            "operation": fact.operation.value,
            "attributes": _attributes(fact),
        }
        for fact in inventory.facts
    ]

    assert actual == expected["expected_facts"]
    assert len(actual) == expected["expected_fact_count"] == 11
    assert {fact.operation for fact in inventory.facts} == set(
        StaticSemanticOperation
    )


def test_instruction_bytes_are_raw_little_endian_decoder_bytes(
    inventory: StaticSemanticInventory,
) -> None:
    by_operation = {
        fact.operation: fact for fact in inventory.facts
        if fact.operation is not StaticSemanticOperation.MEMORY_BARRIER
    }
    assert by_operation[StaticSemanticOperation.MEMORY_LOAD].instruction_bytes == (
        "0x200040f9"
    )
    assert by_operation[
        StaticSemanticOperation.STORE_EXCLUSIVE
    ].instruction_bytes == "0x417c00c8"
    assert by_operation[
        StaticSemanticOperation.EXCEPTION_RETURN
    ].instruction_bytes == "0xe0039fd6"
    assert all(fact.instruction_size == 4 for fact in inventory.facts)
    assert all(len(fact.instruction_address) < 18 for fact in inventory.facts)


def test_materially_different_semantics_are_real_decoder_outputs(
    inventory: StaticSemanticInventory,
) -> None:
    barriers = [
        fact
        for fact in inventory.facts
        if fact.operation is StaticSemanticOperation.MEMORY_BARRIER
    ]
    instruction_barrier = next(
        fact
        for fact in inventory.facts
        if fact.operation is StaticSemanticOperation.INSTRUCTION_BARRIER
    )
    tlbi = next(
        fact
        for fact in inventory.facts
        if fact.operation is StaticSemanticOperation.TLB_INVALIDATE
    )
    eret = next(
        fact
        for fact in inventory.facts
        if fact.operation is StaticSemanticOperation.EXCEPTION_RETURN
    )

    assert [_attributes(fact) for fact in barriers] == [
        {"barrier_kind": "dsb", "barrier_option": "ish"},
        {"barrier_kind": "dmb", "barrier_option": "ish"},
    ]
    assert _attributes(instruction_barrier) == {"barrier_kind": "isb"}
    assert _attributes(tlbi) == {"tlb_operation": "vmalle1is"}
    assert _attributes(eret) == {}
    assert eret.basic_block_address is None
    assert eret.function_name == "owned_exception_return_semantic"


def test_old_a77_fixture_reuses_the_generic_decoder(
    old_inventory: StaticSemanticInventory,
) -> None:
    facts = [
        (fact.operation, _attributes(fact).get("system_register"))
        for fact in old_inventory.facts
    ]

    assert facts == [
        (StaticSemanticOperation.MEMORY_LOAD, None),
        (StaticSemanticOperation.STORE_EXCLUSIVE, None),
        (StaticSemanticOperation.SYSTEM_REGISTER_READ, "par_el1"),
        (StaticSemanticOperation.MEMORY_STORE, None),
        (StaticSemanticOperation.LOAD_EXCLUSIVE, None),
        (StaticSemanticOperation.SYSTEM_REGISTER_WRITE, "par_el1"),
        (StaticSemanticOperation.SYSTEM_REGISTER_READ, "far_el1"),
    ]
    assert old_inventory.decoder_profile_id == (
        AARCH64_STATIC_SEMANTIC_DECODER_PROFILE_AUDITED_PARTIAL_V1
    )
    assert all(
        "source_pattern" not in type(fact).model_fields
        for fact in old_inventory.facts
    )


def test_non_executable_copies_and_distractors_are_ignored(
    inventory: StaticSemanticInventory,
) -> None:
    binary = FIXTURE.read_bytes()
    assert all(int(fact.instruction_address, 16) < 0x401000 for fact in inventory.facts)
    assert binary.count(bytes.fromhex("200040f9")) == 2
    assert binary.count(bytes.fromhex("1f8308d5")) == 2
    assert not any(fact.instruction_bytes == "0x1f2003d5" for fact in inventory.facts)
    assert not any(fact.instruction_bytes == "0x00040091" for fact in inventory.facts)


def test_diagnostics_are_exact_partial_and_outcome_neutral(
    inventory: StaticSemanticInventory,
) -> None:
    assert inventory.diagnostic_codes == [
        "decoded_instruction_count:14",
        (
            "decoder_profile:"
            "phase10d_aarch64_static_semantic_decoder_audited_partial_v1"
        ),
        "deduplicated_semantic_fact_count:0",
        "recognized_semantic_instruction_count:11",
        "semantic_fact_count:11",
        "skipped_non_executable_block_count:0",
        "skipped_non_executable_symbol_range_count:0",
        "unrecognized_instruction_count:3",
    ]
    values = {
        key: value
        for key, value in (
            diagnostic.split(":", 1)
            for diagnostic in inventory.diagnostic_codes
        )
    }
    assert int(values["decoded_instruction_count"]) == (
        int(values["recognized_semantic_instruction_count"])
        + int(values["unrecognized_instruction_count"])
    )
    forbidden = ("verified", "triggerable", "vulnerable", "exploit")
    assert not any(
        value in diagnostic
        for diagnostic in inventory.diagnostic_codes
        for value in forbidden
    )


def test_repeated_decode_is_deterministic(
    inventory: StaticSemanticInventory,
) -> None:
    repeated = AngrAArch64StaticSemanticDecoder().decode(_artifact())

    assert repeated == inventory
    assert repeated.id == EXPECTED_INVENTORY_ID
    assert repeated.model_dump_json() == inventory.model_dump_json()
    assert [fact.instruction_address for fact in inventory.facts] == sorted(
        (fact.instruction_address for fact in inventory.facts),
        key=lambda value: int(value, 16),
    )


def test_artifact_sha_is_derived_from_bytes_not_metadata() -> None:
    artifact = _artifact()
    artifact.metadata["artifact_sha256"] = "0" * 64

    inventory = AngrAArch64StaticSemanticDecoder().decode(artifact)

    assert inventory.artifact_sha256 == EXPECTED_FIXTURE_SHA256
    assert inventory.artifact_sha256 != artifact.metadata["artifact_sha256"]


@pytest.mark.parametrize(
    ("artifact", "error", "message"),
    [
        (
            _artifact(architecture=Architecture.RISC_V),
            UnsupportedArtifactError,
            "ARM artifacts only",
        ),
        (
            _artifact(artifact_type="raw"),
            UnsupportedArtifactError,
            "ELF artifacts only",
        ),
        (
            _artifact(path=None),
            InvalidAnalysisInputError,
            "requires an artifact path",
        ),
        (
            _artifact(path=ROOT / "tests/fixtures/does-not-exist.elf"),
            InvalidAnalysisInputError,
            "not a regular file",
        ),
    ],
)
def test_unsupported_or_missing_inputs_fail_closed(
    artifact: ProgramArtifact,
    error: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error, match=message):
        AngrAArch64StaticSemanticDecoder().decode(artifact)


def test_arm32_elf_is_rejected_after_backend_architecture_detection() -> None:
    with pytest.raises(UnsupportedArtifactError, match="not AArch64"):
        AngrAArch64StaticSemanticDecoder().decode(
            _artifact(path=ARM32_FIXTURE)
        )


def test_malformed_elf_is_invalid_input(tmp_path: Path) -> None:
    malformed = tmp_path / "owned-malformed.elf"
    malformed.write_bytes(b"owned synthetic malformed ELF")

    with pytest.raises(InvalidAnalysisInputError, match="could not load"):
        AngrAArch64StaticSemanticDecoder().decode(_artifact(path=malformed))


def test_missing_optional_backend_has_stable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = decoder_module.importlib.import_module

    def reject_angr(name: str):
        if name == "angr":
            raise ImportError("owned test backend absence")
        return original(name)

    monkeypatch.setattr(decoder_module.importlib, "import_module", reject_angr)
    with pytest.raises(AArch64StaticSemanticBackendError, match="optional"):
        AngrAArch64StaticSemanticDecoder().decode(_artifact())


def test_cfg_backend_failure_has_stable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = SimpleNamespace(
        arch=SimpleNamespace(name="AARCH64", bits=64),
        analyses=SimpleNamespace(
            CFGFast=lambda **_values: (_ for _ in ()).throw(
                RuntimeError("owned CFG failure")
            )
        ),
    )
    fake_angr = SimpleNamespace(Project=lambda *_args, **_kwargs: project)
    decoder = AngrAArch64StaticSemanticDecoder()
    monkeypatch.setattr(decoder, "_load_backend", lambda: (fake_angr, arm64))

    with pytest.raises(AArch64StaticSemanticBackendError, match="CFG analysis"):
        decoder.decode(_artifact())


def test_artifact_mutation_during_decode_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoder = AngrAArch64StaticSemanticDecoder()
    exact = FIXTURE.read_bytes()
    snapshots = iter((exact, exact + b"changed"))
    monkeypatch.setattr(
        decoder,
        "_read_artifact_bytes",
        lambda _path: next(snapshots),
    )

    with pytest.raises(InvalidAnalysisInputError, match="changed"):
        decoder.decode(_artifact())


def test_cfg_and_fallback_overlap_counts_one_unique_instruction() -> None:
    decoder = AngrAArch64StaticSemanticDecoder()
    project, cfg = _overlap_decode_inputs(0xF9400020)

    facts, diagnostics = decoder._decode_inventory_facts(  # noqa: SLF001
        artifact=_artifact(),
        artifact_sha256="a" * 64,
        project=project,
        cfg=cfg,
        arm64=arm64,
        profile=_decoder_profile(arm64),
    )
    values = dict(item.split(":", 1) for item in diagnostics)

    assert values == {
        "decoded_instruction_count": "1",
        "recognized_semantic_instruction_count": "1",
        "unrecognized_instruction_count": "0",
        "skipped_non_executable_block_count": "0",
        "skipped_non_executable_symbol_range_count": "0",
        "deduplicated_semantic_fact_count": "0",
    }
    assert len(facts) == 1
    assert facts[0].operation is StaticSemanticOperation.MEMORY_LOAD
    assert facts[0].basic_block_address == "0x400000"
    assert facts[0].function_name == "owned_cfg_function"


def test_cfg_and_fallback_conflicting_bytes_fail_closed() -> None:
    decoder = AngrAArch64StaticSemanticDecoder()
    project, cfg = _overlap_decode_inputs(0xF9000020)

    with pytest.raises(
        InvalidAnalysisInputError,
        match="conflicting decoded instruction bytes or size",
    ):
        decoder._decode_inventory_facts(  # noqa: SLF001
            artifact=_artifact(),
            artifact_sha256="a" * 64,
            project=project,
            cfg=cfg,
            arm64=arm64,
            profile=_decoder_profile(arm64),
        )


def test_non_executable_symbol_range_has_its_own_counter() -> None:
    decoder = AngrAArch64StaticSemanticDecoder()
    project, cfg = _overlap_decode_inputs(0xF9400020)
    project.loader.main_object.symbols = [
        SimpleNamespace(
            is_function=True,
            name="owned_non_executable_fallback",
            rebased_addr=0x400004,
            size=4,
        )
    ]
    non_executable_section = SimpleNamespace(is_executable=False)
    project.loader.main_object.find_section_containing = (
        lambda _address: non_executable_section
    )
    cfg.kb.functions = {}

    facts, diagnostics = decoder._decode_inventory_facts(  # noqa: SLF001
        artifact=_artifact(),
        artifact_sha256="a" * 64,
        project=project,
        cfg=cfg,
        arm64=arm64,
        profile=_decoder_profile(arm64),
    )
    values = dict(item.split(":", 1) for item in diagnostics)

    assert facts == []
    assert values == {
        "decoded_instruction_count": "0",
        "recognized_semantic_instruction_count": "0",
        "unrecognized_instruction_count": "0",
        "skipped_non_executable_block_count": "0",
        "skipped_non_executable_symbol_range_count": "1",
        "deduplicated_semantic_fact_count": "0",
    }


def test_exact_capstone_identity_tables_cover_audited_families() -> None:
    profile = _decoder_profile(arm64)

    assert _AUDITED_MEMORY_LOAD_IDS == ("ARM64_INS_LDR",)
    assert _AUDITED_MEMORY_STORE_IDS == ("ARM64_INS_STR",)
    assert _AUDITED_LOAD_EXCLUSIVE_IDS == (
        "ARM64_INS_LDXR",
        "ARM64_INS_LDXRB",
        "ARM64_INS_LDXRH",
        "ARM64_INS_LDAXR",
        "ARM64_INS_LDAXRB",
        "ARM64_INS_LDAXRH",
    )
    assert _AUDITED_STORE_EXCLUSIVE_IDS == (
        "ARM64_INS_STXR",
        "ARM64_INS_STXRB",
        "ARM64_INS_STXRH",
        "ARM64_INS_STLXR",
        "ARM64_INS_STLXRB",
        "ARM64_INS_STLXRH",
    )
    assert profile.system_register_names[arm64.ARM64_SYSREG_PAR_EL1] == "par_el1"
    assert profile.barrier_option_names[arm64.ARM64_BARRIER_ISH] == "ish"
    assert profile.tlbi_operation_names[arm64.ARM64_TLBI_VMALLE1IS] == (
        "vmalle1is"
    )


def test_tlbi_typed_no_register_and_register_shapes_are_supported() -> None:
    profile = _decoder_profile(arm64)
    system_no_register = _DecodedAArch64Operand(
        kind=profile.system_operand_kind,
        system=arm64.ARM64_TLBI_VMALLE1IS,
    )
    system_with_register = _DecodedAArch64Operand(
        kind=profile.system_operand_kind,
        system=arm64.ARM64_TLBI_VAE1IS,
    )
    register = _DecodedAArch64Operand(kind=profile.register_operand_kind)
    no_register = _DecodedAArch64Instruction(
        address=0x400000,
        instruction_id=profile.tlbi_id,
        raw_bytes=b"\x00" * 4,
        size=4,
        operands=(system_no_register,),
    )
    with_register = _DecodedAArch64Instruction(
        address=0x400000,
        instruction_id=profile.tlbi_id,
        raw_bytes=b"\x00" * 4,
        size=4,
        operands=(system_with_register, register),
    )

    first = _classify_instruction(no_register, profile=profile)
    second = _classify_instruction(with_register, profile=profile)
    assert first is not None and second is not None
    assert _attributes(SimpleNamespace(attributes=first.attributes)) == {
        "tlb_operation": "vmalle1is"
    }
    assert _attributes(SimpleNamespace(attributes=second.attributes)) == {
        "tlb_operation": "vae1is"
    }


def test_every_exclusive_id_requires_its_exact_primary_shape() -> None:
    profile = _decoder_profile(arm64)
    register = _DecodedAArch64Operand(kind=profile.register_operand_kind)
    memory = _DecodedAArch64Operand(kind=profile.memory_operand_kind)

    for instruction_id in profile.load_exclusive_ids:
        instruction = _DecodedAArch64Instruction(
            address=0x400000,
            instruction_id=instruction_id,
            raw_bytes=b"\x00" * 4,
            size=4,
            operands=(register, memory),
        )
        semantic = _classify_instruction(instruction, profile=profile)
        assert semantic is not None
        assert semantic.operation is StaticSemanticOperation.LOAD_EXCLUSIVE

    for instruction_id in profile.store_exclusive_ids:
        instruction = _DecodedAArch64Instruction(
            address=0x400000,
            instruction_id=instruction_id,
            raw_bytes=b"\x00" * 4,
            size=4,
            operands=(register, register, memory),
        )
        semantic = _classify_instruction(instruction, profile=profile)
        assert semantic is not None
        assert semantic.operation is StaticSemanticOperation.STORE_EXCLUSIVE


@pytest.mark.parametrize(
    ("word", "operation"),
    [
        (0xF9400020, StaticSemanticOperation.MEMORY_LOAD),
        (0xF9000020, StaticSemanticOperation.MEMORY_STORE),
        (0xC85F7C41, StaticSemanticOperation.LOAD_EXCLUSIVE),
        (0xC8007C41, StaticSemanticOperation.STORE_EXCLUSIVE),
        (0xD5387400, StaticSemanticOperation.SYSTEM_REGISTER_READ),
        (0xD5187400, StaticSemanticOperation.SYSTEM_REGISTER_WRITE),
        (0xD5033B9F, StaticSemanticOperation.MEMORY_BARRIER),
        (0xD5033BBF, StaticSemanticOperation.MEMORY_BARRIER),
        (0xD5033FDF, StaticSemanticOperation.INSTRUCTION_BARRIER),
        (0xD508831F, StaticSemanticOperation.TLB_INVALIDATE),
        (0xD69F03E0, StaticSemanticOperation.EXCEPTION_RETURN),
    ],
)
def test_real_capstone_ids_and_shapes_classify_once(
    word: int,
    operation: StaticSemanticOperation,
) -> None:
    semantic = _classify_instruction(
        _decode(word),
        profile=_decoder_profile(arm64),
    )

    assert semantic is not None
    assert semantic.operation is operation


def test_unsupported_operand_shapes_and_identities_are_not_guessed() -> None:
    profile = _decoder_profile(arm64)
    register = _DecodedAArch64Operand(kind=profile.register_operand_kind)
    memory = _DecodedAArch64Operand(kind=profile.memory_operand_kind)
    unknown_system = _DecodedAArch64Operand(
        kind=profile.system_operand_kind,
        system=999999,
    )
    malformed_ldr = _DecodedAArch64Instruction(
        address=0x400000,
        instruction_id=next(iter(profile.memory_load_ids)),
        raw_bytes=b"\x00" * 4,
        size=4,
        operands=(register, register),
    )
    unknown_mrs = _DecodedAArch64Instruction(
        address=0x400000,
        instruction_id=profile.mrs_id,
        raw_bytes=b"\x00" * 4,
        size=4,
        operands=(register, unknown_system),
    )
    non_audited_atomic = _DecodedAArch64Instruction(
        address=0x400000,
        instruction_id=arm64.ARM64_INS_LDAR,
        raw_bytes=b"\x00" * 4,
        size=4,
        operands=(register, memory),
    )

    assert _classify_instruction(malformed_ldr, profile=profile) is None
    assert _classify_instruction(unknown_mrs, profile=profile) is None
    assert _classify_instruction(non_audited_atomic, profile=profile) is None
    assert _classify_instruction(
        _decode(0xD503201F), profile=profile
    ) is None
    assert _classify_instruction(
        _decode(0x91000400), profile=profile
    ) is None


def test_msr_pstate_shape_is_not_system_register_write() -> None:
    profile = _decoder_profile(arm64)
    pstate = _DecodedAArch64Operand(kind=arm64.ARM64_OP_PSTATE)
    immediate = _DecodedAArch64Operand(kind=arm64.ARM64_OP_IMM)
    instruction = _DecodedAArch64Instruction(
        address=0x400000,
        instruction_id=profile.msr_id,
        raw_bytes=b"\x00" * 4,
        size=4,
        operands=(pstate, immediate),
    )

    assert _classify_instruction(instruction, profile=profile) is None


def test_dependency_and_semantic_authority_firewalls() -> None:
    path = (
        ROOT
        / "src/chipchain/analysis/aarch64_static_semantic_decoder.py"
    )
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    forbidden_imports = (
        "chipchain.hardware_trigger",
        "chipchain.knowledge",
        "chipchain.reasoning",
        "chipchain.runtime",
        "chipchain.verification",
        "chipchain.multi_agent",
    )
    forbidden_source = (
        "cve",
        "erratum",
        "pattern",
        "candidate",
        "triggerable",
        "crosslayerinteraction",
        "attackchain",
        ".mnemonic",
        ".op_str",
    )

    assert not any(
        module.startswith(prefix)
        for module in imported
        for prefix in forbidden_imports
    )
    lowered = source.lower()
    assert not any(value in lowered for value in forbidden_source)
    assert "angraprofilestaticsemanticextractor" not in lowered


def test_inventory_contains_no_match_or_outcome_surface(
    inventory: StaticSemanticInventory,
) -> None:
    forbidden = {
        "extraction_plan",
        "source_pattern_id",
        "predicate_candidates",
        "case_candidates",
        "cross_layer_interaction",
        "attack_chain",
        "evidence",
        "verification",
        "triggerability",
    }
    assert forbidden.isdisjoint(type(inventory).model_fields)
    assert forbidden.isdisjoint(type(inventory.facts[0]).model_fields)
    assert all(
        StaticSemanticAttributeName.EFFECTIVE_MEMORY_TYPE_RESOLUTION
        not in {attribute.name for attribute in fact.attributes}
        or _attributes(fact)["effective_memory_type_resolution"]
        == "requires_objective_translation_context"
        for fact in inventory.facts
    )
