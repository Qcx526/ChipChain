"""Optional angr adapter for exact executable ARM A32 trigger matching."""

from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from chipchain.analysis.models import ProgramArtifact
from chipchain.hardware_trigger.errors import (
    HardwareTriggerMatchingError,
    InvalidTriggerMatchingInputError,
    UnsupportedTriggerArtifactError,
)
from chipchain.hardware_trigger.matcher import (
    FirmwareTriggerMatcher,
    _StaticBasicBlock,
    _StaticFunction,
    _StaticInstruction,
    _StaticProgramView,
    _match_program_view,
)
from chipchain.hardware_trigger.models import HardwareTriggerSignature
from chipchain.hardware_trigger.static_models import (
    StaticFirmwareTriggerMatchResult,
)


class AngrFirmwareTriggerMatcher(FirmwareTriggerMatcher):
    """Extract a private function-local CFG view with angr ``CFGFast``."""

    def _match_detached(
        self,
        artifact: ProgramArtifact,
        signature: HardwareTriggerSignature,
    ) -> StaticFirmwareTriggerMatchResult:
        """Hash one ARM ELF, decode executable A32 blocks, and match exactly."""

        artifact_path = self._validate_artifact(artifact)
        artifact_bytes = self._read_artifact_bytes(artifact_path)
        artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        angr = self._load_angr()
        try:
            project = angr.Project(str(artifact_path), auto_load_libs=False)
        except Exception as exc:
            raise InvalidTriggerMatchingInputError(
                "angr could not load the declared ELF artifact"
            ) from exc
        if not project.arch.name.upper().startswith("ARM") or (
            int(project.arch.bits) != 32
        ):
            raise InvalidTriggerMatchingInputError(
                "loaded ELF architecture does not match ARM32 declaration"
            )
        try:
            cfg = project.analyses.CFGFast(normalize=True)
            view = self._extract_program_view(project=project, cfg=cfg)
            if hashlib.sha256(
                self._read_artifact_bytes(artifact_path)
            ).hexdigest() != artifact_sha256:
                raise InvalidTriggerMatchingInputError(
                    "artifact contents changed during static trigger matching"
                )
            return _match_program_view(
                artifact=artifact,
                artifact_sha256=artifact_sha256,
                signature=signature,
                view=view,
            )
        except HardwareTriggerMatchingError:
            raise
        except (ValidationError, ValueError) as exc:
            raise InvalidTriggerMatchingInputError(
                "angr produced an invalid static trigger program view"
            ) from exc
        except Exception as exc:
            raise HardwareTriggerMatchingError(
                "angr static trigger CFG analysis failed"
            ) from exc

    @staticmethod
    def _validate_artifact(artifact: ProgramArtifact) -> Path:
        if artifact.artifact_type != "elf":
            raise UnsupportedTriggerArtifactError(
                "AngrFirmwareTriggerMatcher supports ELF artifacts only"
            )
        if artifact.path is None:
            raise InvalidTriggerMatchingInputError(
                "AngrFirmwareTriggerMatcher requires an artifact path"
            )
        path = Path(artifact.path)
        if not path.is_file():
            raise InvalidTriggerMatchingInputError(
                "AngrFirmwareTriggerMatcher artifact path is not a file"
            )
        return path

    @staticmethod
    def _read_artifact_bytes(path: Path) -> bytes:
        try:
            return path.read_bytes()
        except OSError as exc:
            raise InvalidTriggerMatchingInputError(
                "could not read static trigger artifact bytes"
            ) from exc

    @staticmethod
    def _load_angr() -> Any:
        try:
            return importlib.import_module("angr")
        except (ImportError, OSError) as exc:
            raise HardwareTriggerMatchingError(
                "AngrFirmwareTriggerMatcher requires the optional 'angr' extra"
            ) from exc

    def _extract_program_view(self, *, project: Any, cfg: Any) -> _StaticProgramView:
        """Normalize angr objects without exposing them through public contracts."""

        main_object = project.loader.main_object
        symbol_names = {
            int(symbol.rebased_addr): symbol.name
            for symbol in main_object.symbols
            if symbol.is_function and symbol.name
        }
        functions = [
            function
            for function in cfg.kb.functions.values()
            if self._is_main_object_function(function, main_object)
        ]
        static_functions: list[_StaticFunction] = []
        skipped_non_a32_blocks = 0
        skipped_non_executable_blocks = 0
        skipped_non_4_byte_instructions = 0
        for function in sorted(functions, key=lambda item: int(item.addr)):
            function_address = int(function.addr)
            block_addresses = sorted(int(item) for item in function.block_addrs_set)
            if not block_addresses:
                continue
            graph_nodes = {
                int(node.addr): node
                for node in function.graph.nodes
                if getattr(node, "addr", None) is not None
            }
            cfg_successors: dict[int, set[int]] = {
                address: set() for address in block_addresses
            }
            sequence_successors: dict[int, set[int]] = {
                address: set() for address in block_addresses
            }
            block_address_set = set(block_addresses)
            for source, target, data in function.graph.edges(data=True):
                source_address = int(source.addr)
                target_address = int(target.addr)
                if (
                    source_address not in block_address_set
                    or target_address not in block_address_set
                ):
                    continue
                edge_type = str(data.get("type", ""))
                if edge_type == "call":
                    continue
                cfg_successors[source_address].add(target_address)
                if edge_type not in {"fake_return", "return"}:
                    sequence_successors[source_address].add(target_address)

            blocks: list[_StaticBasicBlock] = []
            for block_address in block_addresses:
                try:
                    block = project.factory.block(block_address)
                except Exception as exc:
                    raise HardwareTriggerMatchingError(
                        "angr could not decode one recovered function block"
                    ) from exc
                executable = self._is_executable_block(main_object, block)
                node = graph_nodes.get(block_address)
                mode_values = [
                    value
                    for value in (
                        getattr(block, "thumb", None),
                        getattr(node, "thumb", None),
                    )
                    if value is not None
                ]
                is_a32 = bool(mode_values) and all(
                    value is False for value in mode_values
                )
                if not executable:
                    skipped_non_executable_blocks += 1
                if not is_a32:
                    skipped_non_a32_blocks += 1
                instructions: list[_StaticInstruction] = []
                if executable and is_a32:
                    try:
                        decoded_instructions = list(block.capstone.insns)
                    except Exception as exc:
                        raise HardwareTriggerMatchingError(
                            "angr could not decode A32 block instructions"
                        ) from exc
                    for instruction in decoded_instructions:
                        raw_bytes = bytes(instruction.bytes)
                        size = int(instruction.size)
                        if size != 4 or len(raw_bytes) != 4:
                            skipped_non_4_byte_instructions += 1
                            word = "0x00000000"
                        else:
                            word = _logical_a32_word(
                                raw_bytes,
                                instruction_endness=(
                                    project.arch.instruction_endness
                                ),
                            )
                        instructions.append(
                            _StaticInstruction(
                                address=int(instruction.address),
                                word=word,
                                size=size,
                                is_a32=True,
                            )
                        )
                blocks.append(
                    _StaticBasicBlock(
                        address=block_address,
                        function_address=function_address,
                        instructions=tuple(instructions),
                        cfg_successors=tuple(cfg_successors[block_address]),
                        sequence_successors=tuple(
                            sequence_successors[block_address]
                        ),
                        is_a32=bool(executable and is_a32),
                    )
                )

            startpoint = getattr(function, "startpoint", None)
            entry_address = (
                int(startpoint.addr)
                if startpoint is not None
                and int(startpoint.addr) in block_address_set
                else function_address
            )
            if entry_address not in block_address_set:
                raise InvalidTriggerMatchingInputError(
                    "recovered function has no function-local entry block"
                )
            static_functions.append(
                _StaticFunction(
                    address=function_address,
                    name=symbol_names.get(function_address),
                    entry_block_address=entry_address,
                    blocks=tuple(blocks),
                )
            )
        return _StaticProgramView(
            functions=tuple(static_functions),
            diagnostics=(
                f"skipped_non_4_byte_instructions:{skipped_non_4_byte_instructions}",
                f"skipped_non_a32_blocks:{skipped_non_a32_blocks}",
                f"skipped_non_executable_blocks:{skipped_non_executable_blocks}",
            ),
        )

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


def _logical_a32_word(raw_bytes: bytes, instruction_endness: object) -> str:
    """Convert four decoded bytes to one logical A32 uint32 instruction word."""

    if not isinstance(raw_bytes, bytes) or len(raw_bytes) != 4:
        raise ValueError("decoded A32 instruction must contain exactly four bytes")
    endness = str(instruction_endness)
    if endness == "Iend_LE":
        byteorder = "little"
    elif endness == "Iend_BE":
        byteorder = "big"
    else:
        raise ValueError("unsupported ARM instruction endianness")
    return f"0x{int.from_bytes(raw_bytes, byteorder=byteorder):08x}"
