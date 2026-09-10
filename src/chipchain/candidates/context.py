"""Source-backed bounded projections using frozen anchor services exclusively.

The sole adapter dependency is the approved read-only raw SI data contract.
The caller parses SI; this module never parses, maps, executes or reads files.
"""

from pydantic import JsonValue

from chipchain.adapters.processorfuzz.models import RawProcessorFuzzSI
from chipchain.anchors import (
    AnchorError, AmbiguousSymbolError, MissingSymbolError, HardwareTestProgramELF,
    SILabelELFAnchor, anchor_si_label, anchor_trace_instruction,
    compose_hardware_case_anchor, revalidate_hardware_test_elf,
)
from chipchain.behavior.processor import ProcessorBehaviorFragment
from chipchain.core import canonical_json_bytes
from chipchain.evidence import AlignmentResult, DivergenceObservation, divergence_context
from chipchain.trigger import TriggerSourceContext
from chipchain.candidates.facts import (
    ContextComposedAnchor, ContextDeclaredBehavior, ContextDivergence,
    ContextELFTraceAnchor, ContextObservation, ContextPair, ContextSIRecord,
    ContextSILabelAnchor, HardwareTriggerCandidateContext, expected_unresolved_conditions,
)


def build_trigger_candidate_context(
    raw_si: RawProcessorFuzzSI, elf: HardwareTestProgramELF, elf_bytes: bytes,
    alignment: AlignmentResult, divergence: DivergenceObservation,
    source: TriggerSourceContext, *, before: int = 5, after: int = 3,
    behavior_fragment: ProcessorBehaviorFragment | None = None,
) -> HardwareTriggerCandidateContext:
    """Reproduce compact hardware-only correlations, never propose requirements.

    At most 8 pairs on each side are selected. Label inventory is enumerated
    once (not runtime history); only successfully composed in-window labels
    enter the output. Missing/ambiguous symbols and unavailable byte anchors
    remain unresolved. Malformed source snapshots fail before anchor handling.
    """

    if type(before) is not int or type(after) is not int or not 0 <= before <= 8 or not 0 <= after <= 8:
        raise ValueError("context bounds must be integers in [0, 8]")
    raw = RawProcessorFuzzSI.model_validate(raw_si)
    source = TriggerSourceContext.model_validate(source)
    view = revalidate_hardware_test_elf(elf, elf_bytes)
    result = AlignmentResult.model_validate(alignment)
    selected = DivergenceObservation.model_validate(divergence)
    if source.artifact.artifact_sha256 != raw.snapshot_sha256:
        raise ValueError("declared SI source differs from raw snapshot")
    if source.architecture != view.source.architecture or source.architecture != result.scope.isa_source.architecture:
        raise ValueError("cross-source architecture mismatch")
    fragment = ProcessorBehaviorFragment.model_validate(behavior_fragment) if behavior_fragment is not None else None
    if fragment is not None:
        if fragment.source.artifact != source.artifact or fragment.source.hardware_target != source.hardware_target:
            raise ValueError("behavior fragment target/provenance differs from declared SI source")
    pairs = divergence_context(result, selected, before=before, after=after)
    pcs = {pair.pc.value for pair in pairs}
    labels: list[SILabelELFAnchor] = []
    for record in raw.instructions:
        if record.label is None:
            continue
        try:
            label = anchor_si_label(raw, view, elf_bytes, si_record_id=record.id, behavior_fragment=fragment)
        except (MissingSymbolError, AmbiguousSymbolError):
            continue
        if label.elf_address.value in pcs:
            labels.append(label)
    compact_pairs: list[ContextPair] = []
    trace_anchors: list[ContextELFTraceAnchor] = []
    composed: list[ContextComposedAnchor] = []
    retained_labels: dict[str, SILabelELFAnchor] = {}
    for pair in pairs:
        left = ContextObservation(observation_id=pair.isa_observation.id, source_id=pair.isa_observation.source_id,
            record_ordinal=pair.isa_observation.record_ordinal, pc=pair.pc,
            instruction_encoding=pair.instruction_encoding, mnemonic=pair.isa_observation.mnemonic)
        right = ContextObservation(observation_id=pair.rtl_observation.id, source_id=pair.rtl_observation.source_id,
            record_ordinal=pair.rtl_observation.record_ordinal, pc=pair.pc, instruction_encoding=pair.instruction_encoding)
        compact_pairs.append(ContextPair(pair_id=pair.id, alignment_scope_id=result.scope.id,
            alignment_ordinal=pair.alignment_ordinal, isa=left, rtl=right, comparisons=pair.comparisons))
        for observation, trace in ((pair.isa_observation, result.isa_artifact), (pair.rtl_observation, result.rtl_artifact)):
            try:
                anchor = anchor_trace_instruction(view, elf_bytes, trace, observation_id=observation.id)
            except AnchorError:
                # Sources/membership are already revalidated; no successful byte
                # anchor is claimed for an unsupported/unmapped/mismatching word.
                continue
            trace_anchors.append(ContextELFTraceAnchor(anchor_id=anchor.id, elf_source_id=anchor.elf_source.id,
                trace_source_id=anchor.trace_source.id, observation_id=observation.id,
                pc=anchor.pc, elf_file_bytes=anchor.elf_file_bytes))
            for label in labels:
                if label.elf_address != anchor.pc:
                    continue
                full = compose_hardware_case_anchor(label, anchor, raw_si=raw, elf=view,
                    elf_bytes=elf_bytes, trace_artifact=trace, behavior_fragment=fragment)
                retained_labels[label.id] = label
                composed.append(ContextComposedAnchor(anchor_id=full.id, si_anchor_id=label.id, trace_anchor_id=anchor.id))
    si_records: list[ContextSIRecord] = []
    si_anchors: list[ContextSILabelAnchor] = []
    behaviors: list[ContextDeclaredBehavior] = []
    for label in retained_labels.values():
        record = label.si_record
        if record.label is None:
            raise ValueError("frozen SI anchor unexpectedly lacks an explicit label")
        si_records.append(ContextSIRecord(record_id=record.id, si_snapshot_id=raw.id,
            instruction_ordinal=record.instruction_ordinal, label=record.label, mnemonic=record.mnemonic))
        binding = label.behavior_binding
        si_anchors.append(ContextSILabelAnchor(anchor_id=label.id, elf_source_id=view.source.id,
            si_snapshot_id=raw.id, si_sha256=raw.snapshot_sha256, si_record_id=record.id, pc=label.elf_address,
            behavior_instruction_id=binding.instruction.id if binding is not None else None))
        if binding is not None:
            behaviors.append(ContextDeclaredBehavior(instruction_id=binding.instruction.id,
                fragment_id=binding.fragment_id, source_context_id=binding.context.id,
                si_record_id=record.id, instruction_ordinal=record.instruction_ordinal,
                mnemonic=binding.instruction.mnemonic))
    # Private assembly only: policy needs the complete compact structure. The
    # unchecked intermediate never escapes; final JSON undergoes full validation.
    draft = HardwareTriggerCandidateContext.model_construct(source=source, si_snapshot_id=raw.id,
        si_sha256=raw.snapshot_sha256, si_byte_length=raw.byte_length, elf_source=view.source,
        alignment_result_id=result.id, alignment_scope=result.scope, alignment_pair_count=len(result.aligned_pairs),
        before=before, after=after, divergence=ContextDivergence(divergence_id=selected.id,
            pair_id=selected.aligned_pair.id, field=selected.field),
        context_records=tuple(compact_pairs), si_records=tuple(si_records), declared_behaviors=tuple(behaviors),
        si_anchors=tuple(si_anchors), trace_anchors=tuple(trace_anchors), composed_anchors=tuple(composed),
        unresolved_conditions=())
    payload = draft.model_dump(mode="json")
    payload["unresolved_conditions"] = [c.model_dump(mode="json") for c in expected_unresolved_conditions(draft)]
    return HardwareTriggerCandidateContext.model_validate(payload)


def candidate_context_view(context: HardwareTriggerCandidateContext) -> dict[str, JsonValue]:
    """Return a detached compact JSON-native view with its deterministic ID."""

    snapshot = HardwareTriggerCandidateContext.model_validate(context)
    return {"context_id": snapshot.id, **snapshot.model_dump(mode="json")}


def serialize_candidate_context(context: HardwareTriggerCandidateContext) -> bytes:
    """Canonical UTF-8 view for future reasoning, with no provider or prompt."""

    return canonical_json_bytes(candidate_context_view(context))
