"""Plan-independent audited partial AArch64 static semantic decoder."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from chipchain.analysis.errors import (
    AArch64StaticSemanticBackendError,
    AArch64StaticSemanticDecoderError,
    InvalidAnalysisInputError,
    UnsupportedArtifactError,
)
from chipchain.analysis.models import ProgramArtifact
from chipchain.analysis.static_semantic_models import (
    StaticSemanticAttribute,
    StaticSemanticAttributeName,
    StaticSemanticFactScope,
    StaticSemanticInstructionFact,
    StaticSemanticInventory,
    StaticSemanticInventoryScope,
    StaticSemanticOperation,
)
from chipchain.models.enums import Architecture


AARCH64_STATIC_SEMANTIC_DECODER_PROFILE_AUDITED_PARTIAL_V1 = (
    "phase10d_aarch64_static_semantic_decoder_audited_partial_v1"
)

_AARCH64_INSTRUCTION_SET = "aarch64"
_MEMORY_TYPE_UNRESOLVED = "requires_objective_translation_context"

_AUDITED_MEMORY_LOAD_IDS = ("ARM64_INS_LDR",)
_AUDITED_MEMORY_STORE_IDS = ("ARM64_INS_STR",)
_AUDITED_LOAD_EXCLUSIVE_IDS = (
    "ARM64_INS_LDXR",
    "ARM64_INS_LDXRB",
    "ARM64_INS_LDXRH",
    "ARM64_INS_LDAXR",
    "ARM64_INS_LDAXRB",
    "ARM64_INS_LDAXRH",
)
_AUDITED_STORE_EXCLUSIVE_IDS = (
    "ARM64_INS_STXR",
    "ARM64_INS_STXRB",
    "ARM64_INS_STXRH",
    "ARM64_INS_STLXR",
    "ARM64_INS_STLXRB",
    "ARM64_INS_STLXRH",
)


@dataclass(frozen=True)
class _AArch64DecoderProfile:
    memory_load_ids: frozenset[int]
    memory_store_ids: frozenset[int]
    load_exclusive_ids: frozenset[int]
    store_exclusive_ids: frozenset[int]
    mrs_id: int
    msr_id: int
    dsb_id: int
    dmb_id: int
    isb_id: int
    tlbi_id: int
    eret_id: int
    register_operand_kind: int
    memory_operand_kind: int
    system_operand_kind: int
    barrier_operand_kind: int
    system_register_names: dict[int, str]
    barrier_option_names: dict[int, str]
    tlbi_operation_names: dict[int, str]


@dataclass(frozen=True)
class _DecodedAArch64Operand:
    kind: int
    register: int | None = None
    system: int | None = None
    barrier: int | None = None


@dataclass(frozen=True)
class _DecodedAArch64Instruction:
    address: int
    instruction_id: int
    raw_bytes: bytes
    size: int
    operands: tuple[_DecodedAArch64Operand, ...]


@dataclass(frozen=True)
class _ClassifiedSemantic:
    operation: StaticSemanticOperation
    attributes: tuple[StaticSemanticAttribute, ...] = ()


class AngrAArch64StaticSemanticDecoder:
    """Decode one immutable AArch64 ELF into generic static semantics."""

    def decode(self, artifact: ProgramArtifact) -> StaticSemanticInventory:
        """Return the audited partial semantic inventory for one artifact."""

        artifact_snapshot, artifact_path = self._validate_input(artifact)
        initial_bytes = self._read_artifact_bytes(artifact_path)
        artifact_sha256 = hashlib.sha256(initial_bytes).hexdigest()
        angr, arm64 = self._load_backend()
        profile = _decoder_profile(arm64)
        try:
            project = angr.Project(str(artifact_path), auto_load_libs=False)
        except Exception as exc:
            raise InvalidAnalysisInputError(
                "angr could not load the declared AArch64 ELF artifact"
            ) from exc
        if (
            str(project.arch.name).upper() != "AARCH64"
            or int(project.arch.bits) != 64
        ):
            raise UnsupportedArtifactError(
                "loaded ELF is not AArch64/64-bit"
            )

        try:
            cfg = project.analyses.CFGFast(normalize=True)
            facts, diagnostics = self._decode_inventory_facts(
                artifact=artifact_snapshot,
                artifact_sha256=artifact_sha256,
                project=project,
                cfg=cfg,
                arm64=arm64,
                profile=profile,
            )
            final_bytes = self._read_artifact_bytes(artifact_path)
            if hashlib.sha256(final_bytes).hexdigest() != artifact_sha256:
                raise InvalidAnalysisInputError(
                    "artifact contents changed during static semantic decoding"
                )
            return StaticSemanticInventory.create(
                architecture=Architecture.ARM,
                artifact_id=artifact_snapshot.id,
                artifact_sha256=artifact_sha256,
                decoder_profile_id=(
                    AARCH64_STATIC_SEMANTIC_DECODER_PROFILE_AUDITED_PARTIAL_V1
                ),
                instruction_set=_AARCH64_INSTRUCTION_SET,
                analysis_scope=(
                    StaticSemanticInventoryScope
                    .PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY
                ),
                facts=facts,
                diagnostic_codes=[
                    (
                        "decoder_profile:"
                        f"{AARCH64_STATIC_SEMANTIC_DECODER_PROFILE_AUDITED_PARTIAL_V1}"
                    ),
                    *diagnostics,
                    f"semantic_fact_count:{len(facts)}",
                ],
            )
        except (
            AArch64StaticSemanticDecoderError,
            InvalidAnalysisInputError,
            UnsupportedArtifactError,
        ):
            raise
        except (ValidationError, ValueError) as exc:
            raise InvalidAnalysisInputError(
                "decoder produced invalid AArch64 static semantic facts"
            ) from exc
        except Exception as exc:
            raise AArch64StaticSemanticBackendError(
                "angr AArch64 static semantic CFG analysis failed"
            ) from exc

    @staticmethod
    def _validate_input(
        artifact: ProgramArtifact,
    ) -> tuple[ProgramArtifact, Path]:
        try:
            snapshot = ProgramArtifact.model_validate(
                artifact.model_dump(mode="json")
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise InvalidAnalysisInputError(
                "static semantic decoding requires a valid detached artifact"
            ) from exc
        if snapshot.architecture is not Architecture.ARM:
            raise UnsupportedArtifactError(
                "AArch64 static semantic decoding supports ARM artifacts only"
            )
        if snapshot.artifact_type != "elf":
            raise UnsupportedArtifactError(
                "AArch64 static semantic decoding supports ELF artifacts only"
            )
        if snapshot.path is None:
            raise InvalidAnalysisInputError(
                "AArch64 static semantic decoding requires an artifact path"
            )
        path = Path(snapshot.path)
        if not path.is_file():
            raise InvalidAnalysisInputError(
                "AArch64 static semantic artifact path is not a regular file"
            )
        return snapshot, path

    @staticmethod
    def _read_artifact_bytes(path: Path) -> bytes:
        try:
            return path.read_bytes()
        except OSError as exc:
            raise InvalidAnalysisInputError(
                "could not read AArch64 static semantic artifact bytes"
            ) from exc

    @staticmethod
    def _load_backend() -> tuple[Any, Any]:
        try:
            angr = importlib.import_module("angr")
            arm64 = importlib.import_module("capstone.arm64")
        except (ImportError, OSError) as exc:
            raise AArch64StaticSemanticBackendError(
                "AArch64 decoding requires the optional 'angr' extra"
            ) from exc
        return angr, arm64

    def _decode_inventory_facts(
        self,
        *,
        artifact: ProgramArtifact,
        artifact_sha256: str,
        project: Any,
        cfg: Any,
        arm64: Any,
        profile: _AArch64DecoderProfile,
    ) -> tuple[list[StaticSemanticInstructionFact], list[str]]:
        main_object = project.loader.main_object
        symbol_names: dict[int, str] = {}
        for address, name in sorted(
            (
                (int(symbol.rebased_addr), str(symbol.name))
                for symbol in main_object.symbols
                if symbol.is_function and symbol.name
            ),
            key=lambda item: (item[0], item[1]),
        ):
            symbol_names.setdefault(address, name)
        functions = sorted(
            (
                function
                for function in cfg.kb.functions.values()
                if self._is_main_object_function(function, main_object)
            ),
            key=lambda item: int(item.addr),
        )
        recovered_function_addresses = {
            int(function.addr) for function in functions
        }
        decoded_identity_by_address: dict[int, tuple[bytes, int]] = {}
        facts_by_address: dict[int, StaticSemanticInstructionFact] = {}
        decoded_instruction_count = 0
        recognized_instruction_count = 0
        unrecognized_instruction_count = 0
        skipped_non_executable_block_count = 0
        skipped_non_executable_symbol_range_count = 0
        deduplicated_semantic_fact_count = 0

        for function in functions:
            function_address = int(function.addr)
            function_name = symbol_names.get(function_address)
            for block_address in sorted(
                {int(value) for value in function.block_addrs_set}
            ):
                try:
                    block = project.factory.block(block_address)
                except Exception as exc:
                    raise AArch64StaticSemanticBackendError(
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
                    raise AArch64StaticSemanticBackendError(
                        "angr could not expose decoded AArch64 instructions"
                    ) from exc
                for instruction in instructions:
                    decoded = _normalize_decoded_instruction(
                        instruction,
                        arm64=arm64,
                    )
                    decoded_identity = (decoded.raw_bytes, decoded.size)
                    previous_identity = decoded_identity_by_address.get(
                        decoded.address
                    )
                    if previous_identity is not None:
                        if previous_identity != decoded_identity:
                            raise InvalidAnalysisInputError(
                                "conflicting decoded instruction bytes or size"
                            )
                        continue
                    decoded_identity_by_address[decoded.address] = decoded_identity
                    decoded_instruction_count += 1
                    semantic = _classify_instruction(
                        decoded,
                        profile=profile,
                    )
                    if semantic is None:
                        unrecognized_instruction_count += 1
                        continue
                    recognized_instruction_count += 1
                    if decoded.size != 4 or len(decoded.raw_bytes) != 4:
                        raise InvalidAnalysisInputError(
                            "recognized AArch64 instruction is not exactly four bytes"
                        )
                    fact = StaticSemanticInstructionFact.create(
                        architecture=Architecture.ARM,
                        artifact_id=artifact.id,
                        artifact_sha256=artifact_sha256,
                        decoder_profile_id=(
                            AARCH64_STATIC_SEMANTIC_DECODER_PROFILE_AUDITED_PARTIAL_V1
                        ),
                        instruction_set=_AARCH64_INSTRUCTION_SET,
                        instruction_address=hex(decoded.address),
                        instruction_bytes=f"0x{decoded.raw_bytes.hex()}",
                        instruction_size=decoded.size,
                        function_address=hex(function_address),
                        function_name=function_name,
                        basic_block_address=hex(block_address),
                        operation=semantic.operation,
                        attributes=list(semantic.attributes),
                        fact_scope=(
                            StaticSemanticFactScope
                            .DECODED_STATIC_INSTRUCTION_SEMANTICS_ONLY
                        ),
                    )
                    previous = facts_by_address.get(decoded.address)
                    if previous is None:
                        facts_by_address[decoded.address] = fact
                    elif previous == fact:
                        deduplicated_semantic_fact_count += 1
                    else:
                        raise InvalidAnalysisInputError(
                            "conflicting semantic facts share an instruction address"
                        )

        symbol_functions = sorted(
            (
                symbol
                for symbol in main_object.symbols
                if symbol.is_function
                and symbol.name
                and int(symbol.size or 0) > 0
                and int(symbol.rebased_addr) not in recovered_function_addresses
            ),
            key=lambda item: (int(item.rebased_addr), str(item.name)),
        )
        for symbol in symbol_functions:
            function_address = int(symbol.rebased_addr)
            function_size = int(symbol.size)
            if not self._is_executable_range(
                main_object,
                function_address,
                function_size,
            ):
                skipped_non_executable_symbol_range_count += 1
                continue
            try:
                raw_function = bytes(
                    project.loader.memory.load(
                        function_address,
                        function_size,
                    )
                )
                instructions = list(
                    project.arch.capstone.disasm(
                        raw_function,
                        function_address,
                    )
                )
            except Exception as exc:
                raise AArch64StaticSemanticBackendError(
                    "angr could not expose one symbol-backed AArch64 function"
                ) from exc
            for instruction in instructions:
                decoded = _normalize_decoded_instruction(
                    instruction,
                    arm64=arm64,
                )
                decoded_identity = (decoded.raw_bytes, decoded.size)
                previous_identity = decoded_identity_by_address.get(
                    decoded.address
                )
                if previous_identity is not None:
                    if previous_identity != decoded_identity:
                        raise InvalidAnalysisInputError(
                            "conflicting decoded instruction bytes or size"
                        )
                    continue
                decoded_identity_by_address[decoded.address] = decoded_identity
                decoded_instruction_count += 1
                semantic = _classify_instruction(decoded, profile=profile)
                if semantic is None:
                    unrecognized_instruction_count += 1
                    continue
                recognized_instruction_count += 1
                if decoded.size != 4 or len(decoded.raw_bytes) != 4:
                    raise InvalidAnalysisInputError(
                        "recognized AArch64 instruction is not exactly four bytes"
                    )
                fact = StaticSemanticInstructionFact.create(
                    architecture=Architecture.ARM,
                    artifact_id=artifact.id,
                    artifact_sha256=artifact_sha256,
                    decoder_profile_id=(
                        AARCH64_STATIC_SEMANTIC_DECODER_PROFILE_AUDITED_PARTIAL_V1
                    ),
                    instruction_set=_AARCH64_INSTRUCTION_SET,
                    instruction_address=hex(decoded.address),
                    instruction_bytes=f"0x{decoded.raw_bytes.hex()}",
                    instruction_size=decoded.size,
                    function_address=hex(function_address),
                    function_name=str(symbol.name),
                    basic_block_address=None,
                    operation=semantic.operation,
                    attributes=list(semantic.attributes),
                    fact_scope=(
                        StaticSemanticFactScope
                        .DECODED_STATIC_INSTRUCTION_SEMANTICS_ONLY
                    ),
                )
                previous = facts_by_address.get(decoded.address)
                if previous is None:
                    facts_by_address[decoded.address] = fact
                elif previous == fact:
                    deduplicated_semantic_fact_count += 1
                else:
                    raise InvalidAnalysisInputError(
                        "conflicting semantic facts share an instruction address"
                    )

        facts = [facts_by_address[key] for key in sorted(facts_by_address)]
        return facts, [
            f"decoded_instruction_count:{decoded_instruction_count}",
            (
                "recognized_semantic_instruction_count:"
                f"{recognized_instruction_count}"
            ),
            f"unrecognized_instruction_count:{unrecognized_instruction_count}",
            (
                "skipped_non_executable_block_count:"
                f"{skipped_non_executable_block_count}"
            ),
            (
                "skipped_non_executable_symbol_range_count:"
                f"{skipped_non_executable_symbol_range_count}"
            ),
            (
                "deduplicated_semantic_fact_count:"
                f"{deduplicated_semantic_fact_count}"
            ),
        ]

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

    @staticmethod
    def _is_executable_range(
        main_object: Any,
        start: int,
        size: int,
    ) -> bool:
        if size <= 0 or not main_object.contains_addr(start):
            return False
        end = start + size - 1
        if not main_object.contains_addr(end):
            return False
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


def _required_instruction_ids(
    arm64: Any,
    names: tuple[str, ...],
) -> frozenset[int]:
    try:
        return frozenset(int(getattr(arm64, name)) for name in names)
    except (AttributeError, TypeError, ValueError) as exc:
        raise AArch64StaticSemanticBackendError(
            "Capstone lacks one or more audited AArch64 instruction identities"
        ) from exc


def _unique_typed_names(arm64: Any, prefix: str) -> dict[int, str]:
    identities: dict[int, list[str]] = {}
    for name in dir(arm64):
        if not name.startswith(prefix) or name.endswith("INVALID"):
            continue
        value = getattr(arm64, name)
        if not isinstance(value, int) or value <= 0:
            continue
        identities.setdefault(value, []).append(name[len(prefix) :].lower())
    return {
        value: names[0]
        for value, names in identities.items()
        if len(names) == 1
    }


def _decoder_profile(arm64: Any) -> _AArch64DecoderProfile:
    """Resolve all exact instruction and typed operand identities for v1."""

    try:
        profile = _AArch64DecoderProfile(
            memory_load_ids=_required_instruction_ids(
                arm64, _AUDITED_MEMORY_LOAD_IDS
            ),
            memory_store_ids=_required_instruction_ids(
                arm64, _AUDITED_MEMORY_STORE_IDS
            ),
            load_exclusive_ids=_required_instruction_ids(
                arm64, _AUDITED_LOAD_EXCLUSIVE_IDS
            ),
            store_exclusive_ids=_required_instruction_ids(
                arm64, _AUDITED_STORE_EXCLUSIVE_IDS
            ),
            mrs_id=int(arm64.ARM64_INS_MRS),
            msr_id=int(arm64.ARM64_INS_MSR),
            dsb_id=int(arm64.ARM64_INS_DSB),
            dmb_id=int(arm64.ARM64_INS_DMB),
            isb_id=int(arm64.ARM64_INS_ISB),
            tlbi_id=int(arm64.ARM64_INS_TLBI),
            eret_id=int(arm64.ARM64_INS_ERET),
            register_operand_kind=int(arm64.ARM64_OP_REG),
            memory_operand_kind=int(arm64.ARM64_OP_MEM),
            system_operand_kind=int(arm64.ARM64_OP_SYS),
            barrier_operand_kind=int(arm64.ARM64_OP_BARRIER),
            system_register_names=_unique_typed_names(
                arm64, "ARM64_SYSREG_"
            ),
            barrier_option_names=_unique_typed_names(
                arm64, "ARM64_BARRIER_"
            ),
            tlbi_operation_names=_unique_typed_names(arm64, "ARM64_TLBI_"),
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise AArch64StaticSemanticBackendError(
            "Capstone lacks the audited AArch64 decoder identities"
        ) from exc
    if not (
        profile.system_register_names
        and profile.barrier_option_names
        and profile.tlbi_operation_names
    ):
        raise AArch64StaticSemanticBackendError(
            "Capstone typed AArch64 identity maps are unavailable"
        )
    return profile


def _normalize_decoded_instruction(
    instruction: Any,
    *,
    arm64: Any,
) -> _DecodedAArch64Instruction:
    """Detach one Capstone instruction into the exact fields used by v1."""

    capstone_instruction = getattr(instruction, "insn", instruction)
    try:
        operands = tuple(
            _DecodedAArch64Operand(
                kind=int(operand.type),
                register=(
                    int(operand.reg)
                    if int(operand.type) == int(arm64.ARM64_OP_REG)
                    else None
                ),
                system=(
                    int(operand.sys)
                    if int(operand.type) == int(arm64.ARM64_OP_SYS)
                    else None
                ),
                barrier=(
                    int(operand.barrier)
                    if int(operand.type) == int(arm64.ARM64_OP_BARRIER)
                    else None
                ),
            )
            for operand in capstone_instruction.operands
        )
        return _DecodedAArch64Instruction(
            address=int(instruction.address),
            instruction_id=int(capstone_instruction.id),
            raw_bytes=bytes(instruction.bytes),
            size=int(instruction.size),
            operands=operands,
        )
    except Exception as exc:
        raise InvalidAnalysisInputError(
            "decoder produced an invalid AArch64 instruction view"
        ) from exc


def _attribute(
    name: StaticSemanticAttributeName,
    value: str,
) -> StaticSemanticAttribute:
    return StaticSemanticAttribute(name=name, value=value)


def _memory_attributes(*, exclusivity: str | None = None) -> tuple[
    StaticSemanticAttribute, ...
]:
    values = [
        _attribute(
            StaticSemanticAttributeName.EFFECTIVE_MEMORY_TYPE_RESOLUTION,
            _MEMORY_TYPE_UNRESOLVED,
        )
    ]
    if exclusivity is not None:
        values.append(
            _attribute(
                StaticSemanticAttributeName.MEMORY_EXCLUSIVITY,
                exclusivity,
            )
        )
    return tuple(values)


def _classify_instruction(
    instruction: _DecodedAArch64Instruction,
    *,
    profile: _AArch64DecoderProfile,
) -> _ClassifiedSemantic | None:
    """Classify only closed exact instruction IDs and typed operand shapes."""

    kinds = tuple(operand.kind for operand in instruction.operands)
    register_memory = (
        profile.register_operand_kind,
        profile.memory_operand_kind,
    )
    if instruction.instruction_id in profile.memory_load_ids:
        if kinds == register_memory:
            return _ClassifiedSemantic(
                StaticSemanticOperation.MEMORY_LOAD,
                _memory_attributes(),
            )
        return None
    if instruction.instruction_id in profile.memory_store_ids:
        if kinds == register_memory:
            return _ClassifiedSemantic(
                StaticSemanticOperation.MEMORY_STORE,
                _memory_attributes(),
            )
        return None
    if instruction.instruction_id in profile.load_exclusive_ids:
        if kinds == register_memory:
            return _ClassifiedSemantic(
                StaticSemanticOperation.LOAD_EXCLUSIVE,
                _memory_attributes(exclusivity="exclusive_load"),
            )
        return None
    if instruction.instruction_id in profile.store_exclusive_ids:
        if kinds == (
            profile.register_operand_kind,
            profile.register_operand_kind,
            profile.memory_operand_kind,
        ):
            return _ClassifiedSemantic(
                StaticSemanticOperation.STORE_EXCLUSIVE,
                _memory_attributes(exclusivity="exclusive_store"),
            )
        return None
    if instruction.instruction_id == profile.mrs_id:
        if kinds != (
            profile.register_operand_kind,
            profile.system_operand_kind,
        ):
            return None
        identity = instruction.operands[1].system
        name = profile.system_register_names.get(identity)
        if name is None:
            return None
        return _ClassifiedSemantic(
            StaticSemanticOperation.SYSTEM_REGISTER_READ,
            (_attribute(StaticSemanticAttributeName.SYSTEM_REGISTER, name),),
        )
    if instruction.instruction_id == profile.msr_id:
        if kinds != (
            profile.system_operand_kind,
            profile.register_operand_kind,
        ):
            return None
        identity = instruction.operands[0].system
        name = profile.system_register_names.get(identity)
        if name is None:
            return None
        return _ClassifiedSemantic(
            StaticSemanticOperation.SYSTEM_REGISTER_WRITE,
            (_attribute(StaticSemanticAttributeName.SYSTEM_REGISTER, name),),
        )
    if instruction.instruction_id in {profile.dsb_id, profile.dmb_id}:
        if kinds != (profile.barrier_operand_kind,):
            return None
        identity = instruction.operands[0].barrier
        option = profile.barrier_option_names.get(identity)
        if option is None:
            return None
        kind = "dsb" if instruction.instruction_id == profile.dsb_id else "dmb"
        return _ClassifiedSemantic(
            StaticSemanticOperation.MEMORY_BARRIER,
            (
                _attribute(StaticSemanticAttributeName.BARRIER_KIND, kind),
                _attribute(StaticSemanticAttributeName.BARRIER_OPTION, option),
            ),
        )
    if instruction.instruction_id == profile.isb_id:
        if kinds != ():
            return None
        return _ClassifiedSemantic(
            StaticSemanticOperation.INSTRUCTION_BARRIER,
            (_attribute(StaticSemanticAttributeName.BARRIER_KIND, "isb"),),
        )
    if instruction.instruction_id == profile.tlbi_id:
        accepted_shapes = {
            (profile.system_operand_kind,),
            (profile.system_operand_kind, profile.register_operand_kind),
        }
        if kinds not in accepted_shapes:
            return None
        identity = instruction.operands[0].system
        name = profile.tlbi_operation_names.get(identity)
        if name is None:
            return None
        return _ClassifiedSemantic(
            StaticSemanticOperation.TLB_INVALIDATE,
            (_attribute(StaticSemanticAttributeName.TLB_OPERATION, name),),
        )
    if instruction.instruction_id == profile.eret_id:
        if kinds == ():
            return _ClassifiedSemantic(
                StaticSemanticOperation.EXCEPTION_RETURN
            )
        return None
    return None
