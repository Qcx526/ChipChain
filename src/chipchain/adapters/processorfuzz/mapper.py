"""Conservative SOURCE_DECLARED projection, not a RISC-V semantic decoder."""

from pydantic import ValidationError

from chipchain.core import Architecture, ProcessorFuzzArtifact
from chipchain.behavior.processor import (
    BehaviorFactNature, BehaviorRelation, BehaviorRelationKind, BehaviorSourceContext,
    BehaviorSourceKind, DeclaredOperand, InstructionBehavior, ProcessorBehaviorFragment,
    RegisterClass, RegisterOperand, RegisterReference,
)
from chipchain.adapters.processorfuzz._syntax import register_kind
from chipchain.adapters.processorfuzz.errors import ProcessorFuzzSIIntegrityError
from chipchain.adapters.processorfuzz.models import RawProcessorFuzzSI


def _operand(token: str) -> RegisterOperand | DeclaredOperand:
    kind = register_kind(token)
    if kind is None:
        return DeclaredOperand(text=token)
    return RegisterOperand(register_ref=RegisterReference(
        architecture=Architecture.RISC_V, register_class=RegisterClass(kind),
        namespace={"gpr": "gpr", "floating_point": "fpr", "system": "csr"}[kind], name=token,
    ))


def map_processorfuzz_si(
    raw_si: RawProcessorFuzzSI, source: ProcessorFuzzArtifact,
) -> ProcessorBehaviorFragment:
    """Detach, revalidate and bind exact raw bytes to caller-declared provenance.

    A matching SHA is only byte binding, not authentication or applicability.
    Unknown target revision/ISA profile remain unknown; no metadata is invented.
    """

    if not isinstance(raw_si, RawProcessorFuzzSI) or not isinstance(source, ProcessorFuzzArtifact):
        raise ProcessorFuzzSIIntegrityError("typed raw SI and ProcessorFuzzArtifact required")
    try:
        raw = RawProcessorFuzzSI.model_validate(raw_si.model_dump(mode="json"))
        artifact = ProcessorFuzzArtifact.model_validate(source.model_dump(mode="json"))
    except (ValidationError, ValueError, TypeError):
        raise ProcessorFuzzSIIntegrityError("invalid detached SI/source snapshot") from None
    if artifact.provenance.architecture != Architecture.RISC_V:
        raise ProcessorFuzzSIIntegrityError("RISC-V source required")
    if raw.snapshot_sha256 != artifact.provenance.artifact_sha256:
        raise ProcessorFuzzSIIntegrityError("raw SI/source SHA mismatch")
    profile = artifact.provenance.producer_profile_id
    if profile is None:
        raise ProcessorFuzzSIIntegrityError("explicit producer profile declaration required")
    context = BehaviorSourceContext(
        source_kind=BehaviorSourceKind.PROCESSORFUZZ_SI, artifact=artifact.provenance,
        hardware_target=artifact.hardware_target, processor_fuzz=artifact, producer_profile_id=profile,
    )
    instructions = tuple(InstructionBehavior(
        source_context_id=context.id, architecture=Architecture.RISC_V,
        nature=BehaviorFactNature.SOURCE_DECLARED, source_ordinal=record.instruction_ordinal,
        mnemonic=record.mnemonic, operands=tuple(_operand(token) for token in record.operand_tokens),
    ) for record in raw.instructions)
    relations = tuple(BehaviorRelation(
        source_context_id=context.id, architecture=Architecture.RISC_V,
        nature=BehaviorFactNature.SOURCE_DECLARED, relation=BehaviorRelationKind.SOURCE_SEQUENCE,
        source_id=left.id, target_id=right.id,
    ) for left, right in zip(instructions, instructions[1:]))
    return ProcessorBehaviorFragment(source=context, elements=instructions, relations=relations)
