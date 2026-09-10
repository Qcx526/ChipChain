"""Hardware-only lexical/byte anchors, never compilation or causal proof.

Persisted models check internal consistency. Public source-backed creation and
composition functions additionally require exact ELF bytes and complete source
snapshots; deserializing a declaration alone does not authenticate its sources.
"""

from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from chipchain.core import Architecture, Identifier, ProgramAddress
from chipchain.behavior.processor import (
    BehaviorFactNature, BehaviorSourceContext, BehaviorSourceKind,
    InstructionBehavior, ProcessorBehaviorFragment,
)
from chipchain.adapters.processorfuzz import RawProcessorFuzzSI, RawSIInstructionRecord, map_processorfuzz_si
from chipchain.evidence import EvidenceArtifactSource, EvidenceLevel, IsaCsvObservation, ParsedCaseArtifact, RtlInstructionObservation
from chipchain.anchors.base import AnchorError, AnchorModel, AmbiguousSymbolError, MissingSymbolError, Sha256
from chipchain.anchors.elf import (
    ELFSymbol, HardwareTestProgramELF, HardwareTestProgramELFSource,
    _lookup, revalidate_hardware_test_elf,
)


class ProcessorBehaviorAnchorBinding(AnchorModel):
    """Reference to an existing SOURCE_DECLARED SI projection, not a new fact."""

    _namespace = "v2-hardware-si-behavior-anchor-binding-v1"
    fragment_id: Identifier
    context: BehaviorSourceContext
    instruction: InstructionBehavior

    @model_validator(mode="after")
    def validate_declaration(self) -> Self:
        if self.context.source_kind != BehaviorSourceKind.PROCESSORFUZZ_SI or self.context.processor_fuzz is None:
            raise ValueError("only a ProcessorFuzz SI behavior context may be bound")
        if self.instruction.nature != BehaviorFactNature.SOURCE_DECLARED or self.instruction.architecture != Architecture.RISC_V:
            raise ValueError("binding requires a RISC-V SOURCE_DECLARED instruction")
        if self.instruction.source_context_id != self.context.id:
            raise ValueError("instruction/context mismatch")
        return self


class SILabelELFAnchor(AnchorModel):
    """Exact label correlation for this labeled record only; never compiled_from."""

    _namespace = "v2-si-label-elf-anchor-v1"
    relation: Literal["SI_LABEL_TO_ELF_SYMBOL_ANCHOR"] = "SI_LABEL_TO_ELF_SYMBOL_ANCHOR"
    anchor_profile_id: Literal["confirmed_si_label_elf_v1"] = "confirmed_si_label_elf_v1"
    si_snapshot_id: Identifier
    si_sha256: Sha256
    si_record: RawSIInstructionRecord
    elf_source: HardwareTestProgramELFSource
    symbol: ELFSymbol
    behavior_binding: ProcessorBehaviorAnchorBinding | None = None
    evidence_level: Literal[EvidenceLevel.CROSS_ARTIFACT_CORRELATED] = EvidenceLevel.CROSS_ARTIFACT_CORRELATED

    @property
    def elf_address(self) -> ProgramAddress:
        return ProgramAddress(value=hex(self.symbol.value))

    @model_validator(mode="after")
    def validate_declaration(self) -> Self:
        if self.si_record.label is None or self.si_record.label != self.symbol.name:
            raise ValueError("SI record must carry the exact symbol label")
        if not 0 < self.symbol.section_index < 0xff00:
            raise ValueError("undefined/reserved symbols cannot supply a program anchor")
        if self.behavior_binding is not None:
            binding = self.behavior_binding
            if binding.context.artifact.artifact_sha256 != self.si_sha256:
                raise ValueError("behavior/SI SHA mismatch")
            if binding.instruction.source_ordinal != self.si_record.instruction_ordinal:
                raise ValueError("behavior/raw SI ordinal mismatch")
        return self


def _trace_word_bytes(word: str) -> bytes:
    # Exact profile rule: printed 32-bit instruction word, ELF little endian.
    value = int(word, 16)
    if value & 3 != 3 or value & 31 == 31:
        raise AnchorError("only 32-bit RISC-V instruction-width markers are supported")
    return value.to_bytes(4, "little")


class ELFTraceInstructionAnchor(AnchorModel):
    """Exact ELF file bytes corresponding to one ISA/RTL observation's PC/word."""

    _namespace = "v2-elf-trace-instruction-anchor-v1"
    relation: Literal["ELF_TO_TRACE_INSTRUCTION_ANCHOR"] = "ELF_TO_TRACE_INSTRUCTION_ANCHOR"
    anchor_profile_id: Literal["confirmed_riscv_trace_word32_le_v1"] = "confirmed_riscv_trace_word32_le_v1"
    elf_source: HardwareTestProgramELFSource
    trace_source: EvidenceArtifactSource
    observation: Annotated[IsaCsvObservation | RtlInstructionObservation, Field(discriminator="kind")]
    elf_file_bytes: Annotated[str, Field(strict=True, min_length=8, max_length=8, pattern=r"^[0-9a-f]{8}$")]
    evidence_level: Literal[EvidenceLevel.CROSS_ARTIFACT_CORRELATED] = EvidenceLevel.CROSS_ARTIFACT_CORRELATED

    @property
    def pc(self) -> ProgramAddress:
        return self.observation.pc

    @property
    def instruction_encoding(self) -> str:
        return self.observation.instruction_encoding

    @model_validator(mode="after")
    def validate_declaration(self) -> Self:
        if self.trace_source.architecture != self.elf_source.architecture or self.observation.source_id != self.trace_source.id:
            raise ValueError("trace source/architecture binding mismatch")
        expected = "confirmed_isa_csv_v1" if isinstance(self.observation, IsaCsvObservation) else "confirmed_rocket_rtl_log_v1"
        if self.trace_source.format_profile_id != expected:
            raise ValueError("unsupported trace profile for ELF instruction anchor")
        if _trace_word_bytes(self.instruction_encoding).hex() != self.elf_file_bytes:
            raise ValueError("ELF bytes differ from profile-scoped little-endian word")
        return self


class HardwareCaseInstructionAnchor(AnchorModel):
    """SI-label/ELF/trace correlation inside a hardware experiment, not firmware."""

    _namespace = "v2-hardware-case-instruction-anchor-v1"
    contract: Literal["v2_hardware_case_instruction_anchor_v1"] = "v2_hardware_case_instruction_anchor_v1"
    anchor_profile_id: Literal["confirmed_hardware_case_anchor_v1"] = "confirmed_hardware_case_anchor_v1"
    si_anchor: SILabelELFAnchor
    trace_anchor: ELFTraceInstructionAnchor
    evidence_level: Literal[EvidenceLevel.CROSS_ARTIFACT_CORRELATED] = EvidenceLevel.CROSS_ARTIFACT_CORRELATED

    @model_validator(mode="after")
    def validate_declaration(self) -> Self:
        if self.si_anchor.elf_source != self.trace_anchor.elf_source:
            raise ValueError("composition requires the same exact hardware-test ELF source")
        if self.si_anchor.elf_address != self.trace_anchor.pc:
            raise ValueError("trace PC must equal the exact label symbol address")
        return self


def _behavior_binding(
    raw: RawProcessorFuzzSI, record: RawSIInstructionRecord, fragment: ProcessorBehaviorFragment | None,
) -> ProcessorBehaviorAnchorBinding | None:
    if fragment is None:
        return None
    fragment = ProcessorBehaviorFragment.model_validate(fragment)
    source = fragment.source
    if source.source_kind != BehaviorSourceKind.PROCESSORFUZZ_SI or source.processor_fuzz is None:
        raise AnchorError("behavior binding requires a ProcessorFuzz SI fragment")
    # Use the frozen mapper, never a second operand reinterpretation algorithm.
    reproduced = map_processorfuzz_si(raw, source.processor_fuzz)
    if reproduced != fragment:
        raise AnchorError("fragment is not the frozen SOURCE_DECLARED projection of this SI")
    matches = [item for item in fragment.elements if isinstance(item, InstructionBehavior) and item.source_ordinal == record.instruction_ordinal]
    if len(matches) != 1:
        raise AnchorError("raw SI ordinal lacks a unique fragment member")
    return ProcessorBehaviorAnchorBinding(fragment_id=fragment.id, context=fragment.source, instruction=matches[0])


def _si_anchor(raw: RawProcessorFuzzSI, view: HardwareTestProgramELF, record_id: str,
               fragment: ProcessorBehaviorFragment | None) -> SILabelELFAnchor:
    matches = [item for item in raw.instructions if item.id == record_id]
    if len(matches) != 1 or matches[0].label is None:
        raise AnchorError("record must be a labeled member of the supplied exact SI")
    record = matches[0]
    symbols = [item for item in view.symbols if item.name == record.label]
    if not symbols:
        raise MissingSymbolError("SI label is absent from this ELF; no address assigned")
    if len(symbols) != 1:
        raise AmbiguousSymbolError("SI label has multiple ELF symbol occurrences")
    symbol = symbols[0]
    if not 0 < symbol.section_index < len(view.sections):
        raise MissingSymbolError("SI label has no ordinary defined program section")
    section = view.sections[symbol.section_index]
    if not section.flags & 2 or not section.address <= symbol.value < section.address + section.size:
        raise MissingSymbolError("SI label has no address inside its allocated section")
    return SILabelELFAnchor(si_snapshot_id=raw.id, si_sha256=raw.snapshot_sha256, si_record=record,
        elf_source=view.source, symbol=symbol, behavior_binding=_behavior_binding(raw, record, fragment))


def anchor_si_label(
    raw_si: RawProcessorFuzzSI, elf: HardwareTestProgramELF, elf_bytes: bytes, *,
    si_record_id: str, behavior_fragment: ProcessorBehaviorFragment | None = None,
) -> SILabelELFAnchor:
    """Revalidate exact SI and ELF, then correlate only one explicit exact label."""

    raw = RawProcessorFuzzSI.model_validate(raw_si)
    view = revalidate_hardware_test_elf(elf, elf_bytes)
    return _si_anchor(raw, view, si_record_id, behavior_fragment)


def _trace_anchor(view: HardwareTestProgramELF, data: bytes, trace: ParsedCaseArtifact, observation_id: str) -> ELFTraceInstructionAnchor:
    if trace.source.format_profile_id not in ("confirmed_isa_csv_v1", "confirmed_rocket_rtl_log_v1"):
        raise AnchorError("only confirmed ISA CSV and RTL instruction profiles are supported")
    matches = [item for item in trace.observations if item.id == observation_id]
    if len(matches) != 1 or not isinstance(matches[0], (IsaCsvObservation, RtlInstructionObservation)):
        raise AnchorError("observation must be an instruction member of this exact trace")
    observation = matches[0]
    expected_bytes = _trace_word_bytes(observation.instruction_encoding)
    actual_bytes = _lookup(view, data, observation.pc, 4)
    if actual_bytes != expected_bytes:
        raise AnchorError("exact ELF bytes disagree with the trace instruction word")
    return ELFTraceInstructionAnchor(elf_source=view.source, trace_source=trace.source,
        observation=observation, elf_file_bytes=actual_bytes.hex())


def anchor_trace_instruction(
    elf: HardwareTestProgramELF, elf_bytes: bytes, trace_artifact: ParsedCaseArtifact, *, observation_id: str,
) -> ELFTraceInstructionAnchor:
    """Independently bind one ISA or RTL observation, never requiring side equality."""

    view = revalidate_hardware_test_elf(elf, elf_bytes)
    trace = ParsedCaseArtifact.model_validate(trace_artifact)
    return _trace_anchor(view, elf_bytes, trace, observation_id)


def compose_hardware_case_anchor(
    si_anchor: SILabelELFAnchor, trace_anchor: ELFTraceInstructionAnchor, *,
    raw_si: RawProcessorFuzzSI, elf: HardwareTestProgramELF, elf_bytes: bytes,
    trace_artifact: ParsedCaseArtifact, behavior_fragment: ProcessorBehaviorFragment | None = None,
) -> HardwareCaseInstructionAnchor:
    """Reproduce both declarations from exact sources before composing them.

    Passing internally consistent, deserialized anchors is not sufficient.
    Unknown or different source snapshots fail closed, including trace occurrence.
    """

    left = SILabelELFAnchor.model_validate(si_anchor)
    right = ELFTraceInstructionAnchor.model_validate(trace_anchor)
    view = revalidate_hardware_test_elf(elf, elf_bytes)
    raw = RawProcessorFuzzSI.model_validate(raw_si)
    trace = ParsedCaseArtifact.model_validate(trace_artifact)
    expected_left = _si_anchor(raw, view, left.si_record.id, behavior_fragment)
    expected_right = _trace_anchor(view, elf_bytes, trace, right.observation.id)
    if left != expected_left or right != expected_right:
        raise AnchorError("anchor declaration differs from the supplied exact source snapshots")
    return HardwareCaseInstructionAnchor(si_anchor=expected_left, trace_anchor=expected_right)
