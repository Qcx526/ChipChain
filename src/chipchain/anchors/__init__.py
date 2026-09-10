"""Hardware-test SI/ELF/trace correlations; no client firmware or causal claims."""

from chipchain.anchors.base import AnchorError, AmbiguousSymbolError, MissingSymbolError
from chipchain.anchors.elf import (
    ELFLoadSegment, ELFSection, ELFSymbol, HardwareTestProgramELF, HardwareTestProgramELFSource,
    parse_hardware_test_elf, read_elf_file_backed_bytes, revalidate_hardware_test_elf,
)
from chipchain.anchors.hardware_case import (
    ELFTraceInstructionAnchor, HardwareCaseInstructionAnchor, ProcessorBehaviorAnchorBinding,
    SILabelELFAnchor, anchor_si_label, anchor_trace_instruction, compose_hardware_case_anchor,
)

__all__ = [
    "AnchorError", "AmbiguousSymbolError", "MissingSymbolError", "ELFLoadSegment", "ELFSection", "ELFSymbol",
    "HardwareTestProgramELF", "HardwareTestProgramELFSource", "parse_hardware_test_elf",
    "read_elf_file_backed_bytes", "revalidate_hardware_test_elf", "ELFTraceInstructionAnchor",
    "HardwareCaseInstructionAnchor", "ProcessorBehaviorAnchorBinding", "SILabelELFAnchor",
    "anchor_si_label", "anchor_trace_instruction", "compose_hardware_case_anchor",
]
