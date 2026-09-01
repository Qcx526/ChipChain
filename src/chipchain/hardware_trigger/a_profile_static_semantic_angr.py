"""Optional angr-backed AArch64 static semantic event extraction.

The adapter emits decoded artifact facts and predicate candidates only. It
does not assemble cases, infer runtime state, resolve effective memory types,
or produce triggerability, feasibility, or verification outcomes.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from chipchain.analysis.models import ProgramArtifact
from chipchain.hardware_trigger.a_profile_semantic_models import (
    AProfileSemanticEventKind,
    AProfileSystemRegister,
)
from chipchain.hardware_trigger.a_profile_static_semantic_models import (
    AProfileStaticInstructionSetState,
    AProfileStaticPredicateCandidate,
    AProfileStaticSemanticExtractionPlan,
    AProfileStaticSemanticExtractionResult,
    AProfileStaticSemanticInstructionFact,
    StaticEffectiveMemoryTypeResolution,
    StaticFactScope,
)
from chipchain.hardware_trigger.errors import (
    AProfileStaticSemanticBackendError,
    AProfileStaticSemanticExtractionError,
    InvalidAProfileStaticSemanticInputError,
    UnsupportedAProfileStaticSemanticArtifactError,
)
from chipchain.models.enums import Architecture


A_PROFILE_STATIC_RECOGNITION_PROFILE_PARTIAL_V1 = (
    "phase10d_a_profile_static_recognition_partial_v1"
)

# Closed Capstone instruction-ID names audited for v1. LDR is accepted only
# with REG, MEM operands. Store-exclusive instructions are accepted only with
# REG, REG, MEM operands. Other load/atomic families remain unsupported.
_AUDITED_LOAD_INSTRUCTION_IDS = ("ARM64_INS_LDR",)
_AUDITED_STORE_EXCLUSIVE_INSTRUCTION_IDS = (
    "ARM64_INS_STXR",
    "ARM64_INS_STXRB",
    "ARM64_INS_STXRH",
    "ARM64_INS_STLXR",
    "ARM64_INS_STLXRB",
    "ARM64_INS_STLXRH",
)


@dataclass(frozen=True)
class _A64RecognitionProfile:
    load_instruction_ids: frozenset[int]
    store_exclusive_instruction_ids: frozenset[int]
    mrs_instruction_id: int
    register_operand_kind: int
    memory_operand_kind: int
    system_register_operand_kind: int
    par_el1_system_register: int


@dataclass(frozen=True)
class _DecodedA64Operand:
    kind: int
    register: int | None = None
    system_register: int | None = None


@dataclass(frozen=True)
class _DecodedA64Instruction:
    address: int
    instruction_id: int
    raw_bytes: bytes
    size: int
    operands: tuple[_DecodedA64Operand, ...]


@dataclass(frozen=True)
class _RecognizedA64Semantic:
    event_kind: AProfileSemanticEventKind
    system_register: AProfileSystemRegister | None = None


class AngrAProfileStaticSemanticExtractor:
    """Extract a conservative decoded AArch64 semantic-fact subset."""

    def extract(
        self,
        artifact: ProgramArtifact,
        extraction_plan: AProfileStaticSemanticExtractionPlan,
    ) -> AProfileStaticSemanticExtractionResult:
        """Analyze one immutable ARM64 ELF and bind facts to an exact plan."""

        artifact_snapshot, plan_snapshot, artifact_path = self._validate_inputs(
            artifact,
            extraction_plan,
        )
        initial_bytes = self._read_artifact_bytes(artifact_path)
        artifact_sha256 = hashlib.sha256(initial_bytes).hexdigest()
        angr, arm64 = self._load_backend()
        profile = _recognition_profile(arm64)
        try:
            project = angr.Project(str(artifact_path), auto_load_libs=False)
        except Exception as exc:
            raise InvalidAProfileStaticSemanticInputError(
                "angr could not load the declared A-profile ELF artifact"
            ) from exc
        if (
            str(project.arch.name).upper() != "AARCH64"
            or int(project.arch.bits) != 64
        ):
            raise UnsupportedAProfileStaticSemanticArtifactError(
                "loaded ELF is not AArch64/64-bit"
            )

        try:
            cfg = project.analyses.CFGFast(normalize=True)
            facts, extraction_diagnostics = self._extract_instruction_facts(
                artifact=artifact_snapshot,
                artifact_sha256=artifact_sha256,
                project=project,
                cfg=cfg,
                arm64=arm64,
                profile=profile,
            )
            final_bytes = self._read_artifact_bytes(artifact_path)
            if hashlib.sha256(final_bytes).hexdigest() != artifact_sha256:
                raise InvalidAProfileStaticSemanticInputError(
                    "artifact contents changed during static semantic extraction"
                )
            candidates = self._bind_predicate_candidates(
                plan=plan_snapshot,
                facts=facts,
            )
            diagnostics = [
                (
                    "static_recognition_profile:"
                    f"{A_PROFILE_STATIC_RECOGNITION_PROFILE_PARTIAL_V1}"
                ),
                *extraction_diagnostics,
                f"semantic_fact_count:{len(facts)}",
                f"predicate_candidate_count:{len(candidates)}",
            ]
            return AProfileStaticSemanticExtractionResult.create(
                artifact_id=artifact_snapshot.id,
                artifact_sha256=artifact_sha256,
                extraction_plan=plan_snapshot,
                instruction_facts=facts,
                predicate_candidates=candidates,
                diagnostic_codes=diagnostics,
            )
        except AProfileStaticSemanticExtractionError:
            raise
        except (ValidationError, ValueError) as exc:
            raise InvalidAProfileStaticSemanticInputError(
                "angr produced invalid A-profile static semantic facts"
            ) from exc
        except Exception as exc:
            raise AProfileStaticSemanticBackendError(
                "angr A-profile static semantic CFG analysis failed"
            ) from exc

    @staticmethod
    def _validate_inputs(
        artifact: ProgramArtifact,
        extraction_plan: AProfileStaticSemanticExtractionPlan,
    ) -> tuple[
        ProgramArtifact,
        AProfileStaticSemanticExtractionPlan,
        Path,
    ]:
        try:
            artifact_snapshot = ProgramArtifact.model_validate(
                artifact.model_dump(mode="json")
            )
            plan_snapshot = AProfileStaticSemanticExtractionPlan.model_validate(
                extraction_plan.model_dump(mode="json")
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise InvalidAProfileStaticSemanticInputError(
                "static semantic extraction requires valid detached inputs"
            ) from exc
        if artifact_snapshot.architecture is not Architecture.ARM:
            raise UnsupportedAProfileStaticSemanticArtifactError(
                "A-profile static semantic extraction supports ARM artifacts only"
            )
        if artifact_snapshot.artifact_type != "elf":
            raise UnsupportedAProfileStaticSemanticArtifactError(
                "A-profile static semantic extraction supports ELF artifacts only"
            )
        if artifact_snapshot.path is None:
            raise InvalidAProfileStaticSemanticInputError(
                "A-profile static semantic extraction requires an artifact path"
            )
        artifact_path = Path(artifact_snapshot.path)
        if not artifact_path.is_file():
            raise InvalidAProfileStaticSemanticInputError(
                "A-profile static semantic artifact path is not a regular file"
            )
        if (
            plan_snapshot.architecture is not Architecture.ARM
            or plan_snapshot.architecture_profile != "a_profile"
            or plan_snapshot.target_instruction_set_state
            is not AProfileStaticInstructionSetState.AARCH64
        ):
            raise InvalidAProfileStaticSemanticInputError(
                "extraction plan is outside the ARM A-profile AArch64 scope"
            )
        return artifact_snapshot, plan_snapshot, artifact_path

    @staticmethod
    def _read_artifact_bytes(path: Path) -> bytes:
        try:
            return path.read_bytes()
        except OSError as exc:
            raise InvalidAProfileStaticSemanticInputError(
                "could not read static semantic artifact bytes"
            ) from exc

    @staticmethod
    def _load_backend() -> tuple[Any, Any]:
        try:
            angr = importlib.import_module("angr")
            arm64 = importlib.import_module("capstone.arm64")
        except (ImportError, OSError) as exc:
            raise AProfileStaticSemanticBackendError(
                "A-profile extraction requires the optional 'angr' extra"
            ) from exc
        return angr, arm64

    def _extract_instruction_facts(
        self,
        *,
        artifact: ProgramArtifact,
        artifact_sha256: str,
        project: Any,
        cfg: Any,
        arm64: Any,
        profile: _A64RecognitionProfile,
    ) -> tuple[list[AProfileStaticSemanticInstructionFact], list[str]]:
        main_object = project.loader.main_object
        symbol_names: dict[int, str] = {}
        for symbol_address, symbol_name in sorted(
            (
                (int(symbol.rebased_addr), str(symbol.name))
                for symbol in main_object.symbols
                if symbol.is_function and symbol.name
            ),
            key=lambda item: (item[0], item[1]),
        ):
            symbol_names.setdefault(symbol_address, symbol_name)
        functions = sorted(
            (
                function
                for function in cfg.kb.functions.values()
                if self._is_main_object_function(function, main_object)
            ),
            key=lambda item: int(item.addr),
        )
        facts_by_address: dict[int, AProfileStaticSemanticInstructionFact] = {}
        decoded_instruction_count = 0
        unsupported_semantic_instruction_count = 0
        skipped_non_executable_block_count = 0
        deduplicated_semantic_fact_count = 0

        for function in functions:
            function_address = int(function.addr)
            function_name = symbol_names.get(function_address)
            for block_address in sorted(
                {int(item) for item in function.block_addrs_set}
            ):
                try:
                    block = project.factory.block(block_address)
                except Exception as exc:
                    raise AProfileStaticSemanticBackendError(
                        "angr could not decode one recovered AArch64 block"
                    ) from exc
                if not self._is_executable_block(main_object, block):
                    skipped_non_executable_block_count += 1
                    continue
                try:
                    instructions = sorted(
                        block.capstone.insns,
                        key=lambda item: int(item.address),
                    )
                except Exception as exc:
                    raise AProfileStaticSemanticBackendError(
                        "angr could not expose decoded AArch64 instructions"
                    ) from exc
                for instruction in instructions:
                    decoded_instruction_count += 1
                    decoded = _normalize_decoded_a64_instruction(
                        instruction,
                        arm64=arm64,
                    )
                    semantic = _classify_decoded_a64_instruction(
                        decoded,
                        profile=profile,
                    )
                    if semantic is None:
                        unsupported_semantic_instruction_count += 1
                        continue
                    word = _logical_a64_word(
                        decoded.raw_bytes,
                        instruction_endness=project.arch.instruction_endness,
                        instruction_size=decoded.size,
                    )
                    memory_type_resolution = (
                        StaticEffectiveMemoryTypeResolution.REQUIRES_OBJECTIVE_TRANSLATION_CONTEXT
                        if semantic.event_kind
                        is AProfileSemanticEventKind.MEMORY_LOAD
                        else StaticEffectiveMemoryTypeResolution.NOT_APPLICABLE
                    )
                    fact = AProfileStaticSemanticInstructionFact.create(
                        artifact_id=artifact.id,
                        artifact_sha256=artifact_sha256,
                        architecture=Architecture.ARM,
                        architecture_profile="a_profile",
                        instruction_set_state=(
                            AProfileStaticInstructionSetState.AARCH64
                        ),
                        instruction_address=_a64_address(decoded.address),
                        instruction_word=word,
                        instruction_size=decoded.size,
                        basic_block_address=_a64_address(block_address),
                        function_address=_a64_address(function_address),
                        function_name=function_name,
                        event_kind=semantic.event_kind,
                        system_register=semantic.system_register,
                        memory_type_resolution=memory_type_resolution,
                        static_fact_scope=(
                            StaticFactScope.DECODED_ARTIFACT_INSTRUCTION_SEMANTICS_ONLY
                        ),
                    )
                    previous = facts_by_address.get(decoded.address)
                    if previous is None:
                        facts_by_address[decoded.address] = fact
                    elif previous == fact:
                        deduplicated_semantic_fact_count += 1
                    else:
                        raise InvalidAProfileStaticSemanticInputError(
                            "conflicting static semantic facts share an address"
                        )

        facts = [facts_by_address[address] for address in sorted(facts_by_address)]
        return facts, [
            f"decoded_instruction_count:{decoded_instruction_count}",
            (
                "unsupported_semantic_instruction_count:"
                f"{unsupported_semantic_instruction_count}"
            ),
            (
                "skipped_non_executable_block_count:"
                f"{skipped_non_executable_block_count}"
            ),
            (
                "deduplicated_semantic_fact_count:"
                f"{deduplicated_semantic_fact_count}"
            ),
        ]

    @staticmethod
    def _bind_predicate_candidates(
        *,
        plan: AProfileStaticSemanticExtractionPlan,
        facts: list[AProfileStaticSemanticInstructionFact],
    ) -> list[AProfileStaticPredicateCandidate]:
        candidates: list[AProfileStaticPredicateCandidate] = []
        for fact in facts:
            for entry in plan.predicate_entries:
                if (
                    fact.event_kind is entry.event_kind
                    and fact.system_register is entry.system_register
                ):
                    candidates.append(
                        AProfileStaticPredicateCandidate.create(
                            extraction_plan=plan,
                            predicate_entry=entry,
                            static_instruction_fact=fact,
                        )
                    )
        return candidates

    @staticmethod
    def _is_main_object_function(function: Any, main_object: Any) -> bool:
        return bool(
            main_object.contains_addr(int(function.addr))
            and not function.is_simprocedure
            and not function.is_plt
        )

    @staticmethod
    def _is_executable_block(main_object: Any, block: Any) -> bool:
        start = int(block.addr)
        size = int(block.size or 0)
        if size <= 0:
            return False
        end = start + size - 1
        start_section = main_object.find_section_containing(start)
        end_section = main_object.find_section_containing(end)
        if start_section is not None or end_section is not None:
            return bool(
                start_section is not None
                and start_section is end_section
                and start_section.is_executable
            )
        start_segment = main_object.find_segment_containing(start)
        end_segment = main_object.find_segment_containing(end)
        return bool(
            start_segment is not None
            and start_segment is end_segment
            and start_segment.is_executable
        )


def _recognition_profile(arm64: Any) -> _A64RecognitionProfile:
    """Resolve the closed v1 Capstone identity table."""

    try:
        return _A64RecognitionProfile(
            load_instruction_ids=frozenset(
                int(getattr(arm64, name))
                for name in _AUDITED_LOAD_INSTRUCTION_IDS
            ),
            store_exclusive_instruction_ids=frozenset(
                int(getattr(arm64, name))
                for name in _AUDITED_STORE_EXCLUSIVE_INSTRUCTION_IDS
            ),
            mrs_instruction_id=int(arm64.ARM64_INS_MRS),
            register_operand_kind=int(arm64.ARM64_OP_REG),
            memory_operand_kind=int(arm64.ARM64_OP_MEM),
            system_register_operand_kind=int(arm64.ARM64_OP_SYS),
            par_el1_system_register=int(arm64.ARM64_SYSREG_PAR_EL1),
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise AProfileStaticSemanticBackendError(
            "Capstone lacks the audited AArch64 recognition identities"
        ) from exc


def _normalize_decoded_a64_instruction(
    instruction: Any,
    *,
    arm64: Any,
) -> _DecodedA64Instruction:
    """Detach one angr/Capstone instruction into a minimal audited view."""

    capstone_instruction = getattr(instruction, "insn", instruction)
    try:
        operands = tuple(
            _DecodedA64Operand(
                kind=int(operand.type),
                register=(
                    int(operand.reg)
                    if int(operand.type) == int(arm64.ARM64_OP_REG)
                    else None
                ),
                system_register=(
                    int(operand.sys)
                    if int(operand.type) == int(arm64.ARM64_OP_SYS)
                    else None
                ),
            )
            for operand in capstone_instruction.operands
        )
        return _DecodedA64Instruction(
            address=int(instruction.address),
            instruction_id=int(capstone_instruction.id),
            raw_bytes=bytes(instruction.bytes),
            size=int(instruction.size),
            operands=operands,
        )
    except Exception as exc:
        raise InvalidAProfileStaticSemanticInputError(
            "decoder produced an invalid AArch64 instruction view"
        ) from exc


def _classify_decoded_a64_instruction(
    instruction: _DecodedA64Instruction,
    *,
    profile: _A64RecognitionProfile,
) -> _RecognizedA64Semantic | None:
    """Classify only the exact closed instruction-ID/operand shapes in v1."""

    operand_kinds = tuple(item.kind for item in instruction.operands)
    if (
        instruction.instruction_id in profile.load_instruction_ids
        and operand_kinds
        == (profile.register_operand_kind, profile.memory_operand_kind)
    ):
        return _RecognizedA64Semantic(AProfileSemanticEventKind.MEMORY_LOAD)
    if (
        instruction.instruction_id
        in profile.store_exclusive_instruction_ids
        and operand_kinds
        == (
            profile.register_operand_kind,
            profile.register_operand_kind,
            profile.memory_operand_kind,
        )
    ):
        return _RecognizedA64Semantic(
            AProfileSemanticEventKind.STORE_EXCLUSIVE
        )
    if (
        instruction.instruction_id == profile.mrs_instruction_id
        and operand_kinds
        == (
            profile.register_operand_kind,
            profile.system_register_operand_kind,
        )
        and instruction.operands[1].system_register
        == profile.par_el1_system_register
    ):
        return _RecognizedA64Semantic(
            AProfileSemanticEventKind.SYSTEM_REGISTER_READ,
            AProfileSystemRegister.PAR_EL1,
        )
    return None


def _logical_a64_word(
    raw_bytes: bytes,
    instruction_endness: object,
    instruction_size: int,
) -> str:
    """Convert exactly four decoded bytes to one logical A64 uint32 word."""

    if instruction_size != 4:
        raise ValueError("decoded A64 instruction size must be exactly four")
    if not isinstance(raw_bytes, bytes) or len(raw_bytes) != 4:
        raise ValueError("decoded A64 instruction must contain exactly four bytes")
    endness = str(instruction_endness)
    if endness == "Iend_LE":
        byteorder = "little"
    elif endness == "Iend_BE":
        byteorder = "big"
    else:
        raise ValueError("unsupported AArch64 instruction endianness")
    return f"0x{int.from_bytes(raw_bytes, byteorder=byteorder):08x}"


def _a64_address(value: int) -> str:
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("AArch64 code address is outside uint64")
    return f"0x{value:016x}"
