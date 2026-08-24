"""Backend-neutral exact A32 trigger-sequence matching over a private CFG view."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from pydantic import ValidationError

from chipchain.analysis import ProgramArtifact
from chipchain.hardware_trigger.enums import ArmExecutionMode
from chipchain.hardware_trigger.errors import (
    InvalidTriggerMatchingInputError,
    UnsupportedTriggerArtifactError,
)
from chipchain.hardware_trigger.models import (
    HardwareTriggerSignature,
    _canonical_hex,
)
from chipchain.hardware_trigger.static_models import (
    StaticFirmwareTriggerMatch,
    StaticFirmwareTriggerMatchResult,
    StaticInstructionLocation,
)
from chipchain.models import Architecture


@dataclass(frozen=True, slots=True)
class _StaticInstruction:
    """One backend-decoded instruction; invalid A32 widths remain observable."""

    address: int
    word: str
    size: int = 4
    is_a32: bool = True

    def __post_init__(self) -> None:
        if not 0 <= self.address <= 0xFFFFFFFF:
            raise ValueError("static instruction address must fit ARM32")
        if self.size <= 0:
            raise ValueError("decoded instruction size must be positive")
        object.__setattr__(
            self,
            "word",
            _canonical_hex(self.word, digits=8, label="A32 instruction word"),
        )


@dataclass(frozen=True, slots=True)
class _StaticBasicBlock:
    """One function-owned decoded block with separate reachability edges."""

    address: int
    function_address: int
    instructions: tuple[_StaticInstruction, ...]
    cfg_successors: tuple[int, ...] = ()
    sequence_successors: tuple[int, ...] | None = None
    is_a32: bool = True

    def __post_init__(self) -> None:
        for address in (self.address, self.function_address):
            if not 0 <= address <= 0xFFFFFFFF:
                raise ValueError("static block addresses must fit ARM32")
        instruction_addresses = [item.address for item in self.instructions]
        if instruction_addresses != sorted(instruction_addresses):
            raise ValueError("decoded block instructions must be address ordered")
        if len(instruction_addresses) != len(set(instruction_addresses)):
            raise ValueError("decoded block instruction addresses must be unique")
        cfg_successors = tuple(sorted(set(self.cfg_successors)))
        sequence_successors = (
            cfg_successors
            if self.sequence_successors is None
            else tuple(sorted(set(self.sequence_successors)))
        )
        if not set(sequence_successors).issubset(cfg_successors):
            raise ValueError("sequence successors must be CFG successors")
        object.__setattr__(self, "cfg_successors", cfg_successors)
        object.__setattr__(self, "sequence_successors", sequence_successors)


@dataclass(frozen=True, slots=True)
class _StaticFunction:
    """One recovered function and its private function-local CFG view."""

    address: int
    name: str | None
    entry_block_address: int
    blocks: tuple[_StaticBasicBlock, ...]

    def __post_init__(self) -> None:
        if not 0 <= self.address <= 0xFFFFFFFF:
            raise ValueError("static function address must fit ARM32")
        ordered = tuple(sorted(self.blocks, key=lambda item: item.address))
        addresses = [item.address for item in ordered]
        if len(addresses) != len(set(addresses)):
            raise ValueError("static function block addresses must be unique")
        if self.entry_block_address not in set(addresses):
            raise ValueError("static function entry must identify one function block")
        if any(item.function_address != self.address for item in ordered):
            raise ValueError("static blocks must remain within one function")
        object.__setattr__(self, "blocks", ordered)


@dataclass(frozen=True, slots=True)
class _StaticProgramView:
    """Small backend-neutral seam used only by exact trigger matching."""

    functions: tuple[_StaticFunction, ...]
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        ordered = tuple(sorted(self.functions, key=lambda item: item.address))
        addresses = [item.address for item in ordered]
        if len(addresses) != len(set(addresses)):
            raise ValueError("static program function addresses must be unique")
        object.__setattr__(self, "functions", ordered)
        object.__setattr__(self, "diagnostics", tuple(sorted(set(self.diagnostics))))


class FirmwareTriggerMatcher(ABC):
    """Vendor-neutral detached matcher contract for one artifact/signature pair."""

    def match(
        self,
        artifact: ProgramArtifact,
        signature: HardwareTriggerSignature,
    ) -> StaticFirmwareTriggerMatchResult:
        """Revalidate detached inputs and delegate only architecture-safe analysis."""

        if not isinstance(artifact, ProgramArtifact):
            raise InvalidTriggerMatchingInputError(
                "static trigger matching requires a ProgramArtifact"
            )
        if not isinstance(signature, HardwareTriggerSignature):
            raise InvalidTriggerMatchingInputError(
                "static trigger matching requires a HardwareTriggerSignature"
            )
        try:
            artifact_snapshot = ProgramArtifact.model_validate(
                artifact.model_dump(mode="json")
            )
            signature_snapshot = HardwareTriggerSignature.model_validate(
                signature.model_dump(mode="json")
            )
        except ValidationError as exc:
            raise InvalidTriggerMatchingInputError(
                "static trigger matching input failed detached revalidation"
            ) from exc
        if artifact_snapshot.architecture is not Architecture.ARM:
            raise UnsupportedTriggerArtifactError(
                "static trigger matching supports ARM artifacts only"
            )
        if artifact_snapshot.architecture is not signature_snapshot.architecture:
            raise UnsupportedTriggerArtifactError(
                "artifact and hardware trigger signature architecture mismatch"
            )
        if signature_snapshot.execution_mode is not ArmExecutionMode.A32:
            raise UnsupportedTriggerArtifactError(
                "static trigger matching supports ARM A32 signatures only"
            )
        return self._match_detached(artifact_snapshot, signature_snapshot)

    @abstractmethod
    def _match_detached(
        self,
        artifact: ProgramArtifact,
        signature: HardwareTriggerSignature,
    ) -> StaticFirmwareTriggerMatchResult:
        """Match already detached and architecture-consistent inputs."""


def _match_program_view(
    *,
    artifact: ProgramArtifact,
    artifact_sha256: str,
    signature: HardwareTriggerSignature,
    view: _StaticProgramView,
) -> StaticFirmwareTriggerMatchResult:
    """Return all finite exact occurrences on reachable function-local paths."""

    matches_by_id: dict[str, StaticFirmwareTriggerMatch] = {}
    unreachable_blocks = 0
    for function in view.functions:
        block_by_address = {item.address: item for item in function.blocks}
        reachable = _reachable_a32_blocks(function, block_by_address)
        unreachable_blocks += len(block_by_address) - len(reachable)
        for block_address in sorted(reachable):
            block = block_by_address[block_address]
            for instruction_index, instruction in enumerate(block.instructions):
                if not _is_matchable_a32_instruction(block, instruction):
                    continue
                if instruction.word != signature.instruction_sequence[0]:
                    continue
                for match in _walk_exact_occurrence(
                    artifact=artifact,
                    artifact_sha256=artifact_sha256,
                    signature=signature,
                    function=function,
                    block_by_address=block_by_address,
                    reachable=reachable,
                    start_block_address=block_address,
                    start_instruction_index=instruction_index,
                ):
                    matches_by_id.setdefault(match.id, match)

    diagnostics = [
        *view.diagnostics,
        f"exact_matches:{len(matches_by_id)}",
        f"recovered_blocks:{sum(len(item.blocks) for item in view.functions)}",
        f"recovered_functions:{len(view.functions)}",
        f"unreachable_or_unsupported_blocks:{unreachable_blocks}",
    ]
    return StaticFirmwareTriggerMatchResult(
        artifact_id=artifact.id,
        artifact_sha256=artifact_sha256,
        signature_id=signature.id,
        hardware_vulnerability_id=signature.hardware_vulnerability_id,
        architecture=artifact.architecture,
        execution_mode=signature.execution_mode,
        matches=list(matches_by_id.values()),
        diagnostics=diagnostics,
    )


def _reachable_a32_blocks(
    function: _StaticFunction,
    block_by_address: dict[int, _StaticBasicBlock],
) -> set[int]:
    """Compute structural reachability from the recovered function entry."""

    entry = block_by_address[function.entry_block_address]
    if not entry.is_a32:
        return set()
    reachable: set[int] = set()
    pending = [entry.address]
    while pending:
        address = pending.pop(0)
        if address in reachable:
            continue
        block = block_by_address.get(address)
        if block is None or not block.is_a32:
            continue
        reachable.add(address)
        pending.extend(
            successor
            for successor in block.cfg_successors
            if successor not in reachable
        )
        pending.sort()
    return reachable


def _walk_exact_occurrence(
    *,
    artifact: ProgramArtifact,
    artifact_sha256: str,
    signature: HardwareTriggerSignature,
    function: _StaticFunction,
    block_by_address: dict[int, _StaticBasicBlock],
    reachable: set[int],
    start_block_address: int,
    start_instruction_index: int,
) -> list[StaticFirmwareTriggerMatch]:
    """Walk at most the finite signature length without symbolic execution."""

    state_type = tuple[
        int,
        int,
        int,
        tuple[StaticInstructionLocation, ...],
        tuple[int, ...],
    ]
    pending: list[state_type] = [
        (start_block_address, start_instruction_index, 0, (), ())
    ]
    visited: set[tuple[object, ...]] = set()
    matches: list[StaticFirmwareTriggerMatch] = []
    while pending:
        block_address, instruction_index, signature_index, locations, path = (
            pending.pop()
        )
        state_key = (
            block_address,
            instruction_index,
            signature_index,
            tuple(item.instruction_address for item in locations),
            path,
        )
        if state_key in visited:
            continue
        visited.add(state_key)
        block = block_by_address.get(block_address)
        if block is None or block_address not in reachable or not block.is_a32:
            continue
        if not 0 <= instruction_index < len(block.instructions):
            continue
        instruction = block.instructions[instruction_index]
        if not _is_matchable_a32_instruction(block, instruction):
            continue
        if instruction.word != signature.instruction_sequence[signature_index]:
            continue

        location = StaticInstructionLocation(
            instruction_address=f"0x{instruction.address:08x}",
            instruction_word=instruction.word,
            basic_block_address=f"0x{block.address:08x}",
        )
        next_locations = (*locations, location)
        next_path = path
        if not next_path or next_path[-1] != block.address:
            next_path = (*next_path, block.address)
        if signature_index + 1 == len(signature.instruction_sequence):
            matches.append(
                StaticFirmwareTriggerMatch.create(
                    artifact_id=artifact.id,
                    artifact_sha256=artifact_sha256,
                    signature_id=signature.id,
                    hardware_vulnerability_id=(
                        signature.hardware_vulnerability_id
                    ),
                    architecture=artifact.architecture,
                    execution_mode=signature.execution_mode,
                    function_address=f"0x{function.address:08x}",
                    function_name=function.name,
                    instruction_locations=list(next_locations),
                    basic_block_path=[f"0x{item:08x}" for item in next_path],
                    metadata={"structural_scope": "function_local_cfg"},
                )
            )
            continue

        next_signature_index = signature_index + 1
        if instruction_index + 1 < len(block.instructions):
            pending.append(
                (
                    block.address,
                    instruction_index + 1,
                    next_signature_index,
                    next_locations,
                    next_path,
                )
            )
            continue
        for successor in reversed(block.sequence_successors or ()):
            if successor in reachable:
                pending.append(
                    (
                        successor,
                        0,
                        next_signature_index,
                        next_locations,
                        next_path,
                    )
                )
    return matches


def _is_matchable_a32_instruction(
    block: _StaticBasicBlock,
    instruction: _StaticInstruction,
) -> bool:
    return bool(block.is_a32 and instruction.is_a32 and instruction.size == 4)
