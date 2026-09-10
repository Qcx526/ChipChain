"""Compact projections of frozen source objects, not independently authenticated facts.

Original object IDs remain references. Only the source-backed builder reproduces
them from complete snapshots; JSON validation checks internal closure, not source
authenticity. No raw log, SI operand stream or ELF payload is retained here.
"""

from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from chipchain.core import DomainModel, Identifier, ProgramAddress, canonical_json_bytes
from chipchain.anchors import HardwareTestProgramELFSource
from chipchain.evidence import AlignmentScope, ComparableField, ComparisonOutcome, FieldComparison
from chipchain.trigger import TriggerSourceContext
from chipchain.candidates.base import CandidateModel, ContextBound, Ordinal, Sha256, Word
from chipchain.candidates.enums import ObjectiveFactKind as K, UnresolvedConditionKind as U


class ObjectiveFactReference(CandidateModel):
    """Kind plus source/parent ownership disambiguates repeated comparison IDs."""

    _namespace = "v2-candidate-fact-reference-v1"
    kind: K
    fact_id: Identifier
    owner_id: Identifier


class ContextObservation(DomainModel):
    """A printed instruction occurrence; no runtime causal interpretation."""

    observation_id: Identifier
    source_id: Identifier
    record_ordinal: Ordinal
    pc: ProgramAddress
    instruction_encoding: Word
    mnemonic: Identifier | None = None


class ContextPair(DomainModel):
    pair_id: Identifier
    alignment_scope_id: Identifier
    alignment_ordinal: Ordinal
    isa: ContextObservation
    rtl: ContextObservation
    comparisons: tuple[FieldComparison, ...]


class ContextDivergence(DomainModel):
    divergence_id: Identifier
    pair_id: Identifier
    field: ComparableField


class ContextSIRecord(DomainModel):
    record_id: Identifier
    si_snapshot_id: Identifier
    instruction_ordinal: Ordinal
    label: Annotated[str, Field(strict=True, max_length=128, pattern=r"^_[pls][0-9]+$")]
    mnemonic: Identifier


class ContextDeclaredBehavior(DomainModel):
    instruction_id: Identifier
    fragment_id: Identifier
    source_context_id: Identifier
    si_record_id: Identifier
    instruction_ordinal: Ordinal
    mnemonic: Identifier
    nature: Literal["source_declared"] = "source_declared"


class ContextSILabelAnchor(DomainModel):
    anchor_id: Identifier
    elf_source_id: Identifier
    si_snapshot_id: Identifier
    si_sha256: Sha256
    si_record_id: Identifier
    pc: ProgramAddress
    behavior_instruction_id: Identifier | None = None


class ContextELFTraceAnchor(DomainModel):
    anchor_id: Identifier
    elf_source_id: Identifier
    trace_source_id: Identifier
    observation_id: Identifier
    pc: ProgramAddress
    elf_file_bytes: Word


class ContextComposedAnchor(DomainModel):
    anchor_id: Identifier
    si_anchor_id: Identifier
    trace_anchor_id: Identifier


class UnresolvedCondition(CandidateModel):
    """A closed open condition; absence of proof is not a negative verdict."""

    _namespace = "v2-candidate-unresolved-condition-v1"
    kind: U
    alignment_scope_id: Identifier
    observation_ref: ObjectiveFactReference | None = None
    pc: ProgramAddress | None = None

    @model_validator(mode="after")
    def validate_location(self) -> Self:
        local = self.kind in (U.NO_DIRECT_SI_LABEL_ANCHOR, U.ELF_TRACE_ANCHOR_UNAVAILABLE)
        if local != (self.observation_ref is not None) or local != (self.pc is not None):
            raise ValueError("only missing-anchor conditions require an observation and PC")
        if self.observation_ref is not None and self.observation_ref.kind not in (K.ISA_OBSERVATION, K.RTL_OBSERVATION):
            raise ValueError("missing-anchor condition must reference an instruction observation")
        return self


def _unique(items: tuple, key: str) -> None:
    ids = [getattr(item, key) for item in items]
    if len(ids) != len(set(ids)):
        raise ValueError(f"duplicate {key}")


class HardwareTriggerCandidateContext(CandidateModel):
    """Bounded hardware-side source projections, never trigger extraction."""

    _namespace = "v2-hardware-trigger-candidate-context-v1"
    contract: Literal["v2_hardware_trigger_candidate_context_v1"] = "v2_hardware_trigger_candidate_context_v1"
    source: TriggerSourceContext
    si_snapshot_id: Identifier
    si_sha256: Sha256
    si_byte_length: Annotated[int, Field(strict=True, gt=0)]
    elf_source: HardwareTestProgramELFSource
    alignment_result_id: Identifier
    alignment_scope: AlignmentScope
    alignment_pair_count: Annotated[int, Field(strict=True, gt=0)]
    before: ContextBound = 5
    after: ContextBound = 3
    divergence: ContextDivergence
    context_records: Annotated[tuple[ContextPair, ...], Field(min_length=1, max_length=17)]
    si_records: Annotated[tuple[ContextSIRecord, ...], Field(max_length=256)] = ()
    declared_behaviors: Annotated[tuple[ContextDeclaredBehavior, ...], Field(max_length=256)] = ()
    si_anchors: Annotated[tuple[ContextSILabelAnchor, ...], Field(max_length=256)] = ()
    trace_anchors: Annotated[tuple[ContextELFTraceAnchor, ...], Field(max_length=34)] = ()
    composed_anchors: Annotated[tuple[ContextComposedAnchor, ...], Field(max_length=512)] = ()
    unresolved_conditions: Annotated[tuple[UnresolvedCondition, ...], Field(max_length=80)]

    @field_validator("si_records", "declared_behaviors", "si_anchors", "trace_anchors", "composed_anchors", "unresolved_conditions")
    @classmethod
    def canonical_set(cls, items: tuple) -> tuple:
        # All these collections are sets, unlike the ordered context records.
        blobs = [canonical_json_bytes(item.model_dump(mode="json")) for item in items]
        if len(blobs) != len(set(blobs)):
            raise ValueError("duplicate context entry")
        return tuple(item for _, item in sorted(zip(blobs, items), key=lambda pair: pair[0]))

    def fact_index(self) -> dict[ObjectiveFactReference, DomainModel]:
        """Resolve only scoped typed references, not arbitrary ID-like strings."""

        index: dict[ObjectiveFactReference, DomainModel] = {}

        def add(kind: K, fact_id: str, owner: str, value: DomainModel) -> None:
            ref = ObjectiveFactReference(kind=kind, fact_id=fact_id, owner_id=owner)
            if ref in index:
                raise ValueError("duplicate objective reference")
            index[ref] = value

        for pair in self.context_records:
            add(K.ALIGNED_PAIR, pair.pair_id, self.alignment_result_id, pair)
            add(K.ISA_OBSERVATION, pair.isa.observation_id, pair.isa.source_id, pair.isa)
            add(K.RTL_OBSERVATION, pair.rtl.observation_id, pair.rtl.source_id, pair.rtl)
            for item in pair.comparisons:
                add(K.FIELD_COMPARISON, item.id, pair.pair_id, item)
        add(K.DIVERGENCE_OBSERVATION, self.divergence.divergence_id, self.alignment_result_id, self.divergence)
        for record in self.si_records:
            add(K.SI_RAW_RECORD, record.record_id, self.si_snapshot_id, record)
        for record in self.declared_behaviors:
            add(K.SOURCE_DECLARED_BEHAVIOR, record.instruction_id, record.fragment_id, record)
        for kind, records in ((K.SI_ELF_LABEL_ANCHOR, self.si_anchors), (K.ELF_TRACE_ANCHOR, self.trace_anchors),
                              (K.HARDWARE_CASE_INSTRUCTION_ANCHOR, self.composed_anchors)):
            for anchor in records:
                add(kind, anchor.anchor_id, self.elf_source.id, anchor)
        return index

    @model_validator(mode="after")
    def validate_integrity(self) -> Self:
        """Check compact referential closure; external authenticity needs sources."""

        if self.source.artifact.artifact_sha256 != self.si_sha256:
            raise ValueError("candidate SI source SHA mismatch")
        if self.source.architecture != self.elf_source.architecture or self.source.architecture != self.alignment_scope.isa_source.architecture:
            raise ValueError("candidate source architecture mismatch")
        # Core labels are broader provenance declarations. The reasoning view
        # is not a channel for host paths or control-delimited source payloads.
        for label in (self.source.hardware_target.hardware_model, self.source.hardware_target.hardware_revision):
            if label is not None and (any(c in label for c in "/\\~") or any(ord(c) < 32 or ord(c) == 127 for c in label)):
                raise ValueError("compact source labels cannot contain paths/control characters")
        _unique(self.context_records, "pair_id")
        for pair in self.context_records:
            if pair.alignment_scope_id != self.alignment_scope.id:
                raise ValueError("pair belongs to another alignment scope")
            if pair.isa.source_id != self.alignment_scope.isa_source.id or pair.rtl.source_id != self.alignment_scope.rtl_source.id:
                raise ValueError("pair observation source mismatch")
            if (pair.isa.pc, pair.isa.instruction_encoding) != (pair.rtl.pc, pair.rtl.instruction_encoding):
                raise ValueError("pair PC/word mismatch")
            if tuple(item.field for item in pair.comparisons) != self.alignment_scope.comparable_fields:
                raise ValueError("comparison fields differ from scope")
        selected = [p for p in self.context_records if p.pair_id == self.divergence.pair_id]
        if len(selected) != 1:
            raise ValueError("divergence pair is outside context")
        center = selected[0].alignment_ordinal
        expected = tuple(range(max(0, center - self.before), min(self.alignment_pair_count, center + self.after + 1)))
        if tuple(p.alignment_ordinal for p in self.context_records) != expected or center >= self.alignment_pair_count:
            raise ValueError("context does not match the exact declared bounded window")
        if not any(c.field == self.divergence.field and c.outcome == ComparisonOutcome.DIFFERENT for c in selected[0].comparisons):
            raise ValueError("selected field is not an observed difference")
        index = self.fact_index()
        observations = {o.observation_id: o for p in self.context_records for o in (p.isa, p.rtl)}
        si_records = {r.record_id: r for r in self.si_records}
        _unique(self.si_records, "record_id")
        _unique(self.si_records, "instruction_ordinal")
        if any(r.si_snapshot_id != self.si_snapshot_id for r in self.si_records):
            raise ValueError("raw SI record belongs to another snapshot")
        _unique(self.declared_behaviors, "instruction_id")
        behaviors = {b.instruction_id: b for b in self.declared_behaviors}
        if len({(b.fragment_id, b.source_context_id) for b in self.declared_behaviors}) > 1:
            raise ValueError("mixed behavior fragments")
        for b in self.declared_behaviors:
            record = si_records.get(b.si_record_id)
            if record is None or (record.instruction_ordinal, record.mnemonic) != (b.instruction_ordinal, b.mnemonic):
                raise ValueError("behavior/raw record mismatch")
        _unique(self.si_anchors, "anchor_id")
        _unique(self.trace_anchors, "anchor_id")
        _unique(self.trace_anchors, "observation_id")
        _unique(self.composed_anchors, "anchor_id")
        si_anchors = {a.anchor_id: a for a in self.si_anchors}
        trace_anchors = {a.anchor_id: a for a in self.trace_anchors}
        for a in self.si_anchors:
            if (a.elf_source_id, a.si_snapshot_id, a.si_sha256) != (self.elf_source.id, self.si_snapshot_id, self.si_sha256):
                raise ValueError("SI anchor source mismatch")
            if a.si_record_id not in si_records:
                raise ValueError("SI anchor record missing")
            if a.behavior_instruction_id is not None:
                b = behaviors.get(a.behavior_instruction_id)
                if b is None or b.si_record_id != a.si_record_id:
                    raise ValueError("SI anchor behavior mismatch")
        for a in self.trace_anchors:
            o = observations.get(a.observation_id)
            if o is None or a.elf_source_id != self.elf_source.id or (a.trace_source_id, a.pc) != (o.source_id, o.pc):
                raise ValueError("ELF trace anchor source/occurrence mismatch")
            if a.elf_file_bytes != int(o.instruction_encoding, 16).to_bytes(4, "little").hex():
                raise ValueError("ELF byte projection mismatch")
        for a in self.composed_anchors:
            left, right = si_anchors.get(a.si_anchor_id), trace_anchors.get(a.trace_anchor_id)
            if left is None or right is None or left.pc != right.pc:
                raise ValueError("composed anchor endpoints mismatch")
        if set(si_records) != {a.si_record_id for a in self.si_anchors} or set(behaviors) != {a.behavior_instruction_id for a in self.si_anchors if a.behavior_instruction_id is not None}:
            raise ValueError("unrelated SI/behavior records are not context facts")
        if set(si_anchors) != {a.si_anchor_id for a in self.composed_anchors}:
            raise ValueError("SI anchors must participate in bounded trace composition")
        # Derive only missing-coverage and source limitations, not trigger claims.
        if self.unresolved_conditions != expected_unresolved_conditions(self):
            raise ValueError("unresolved conditions must preserve the closed v1 policy")
        for condition in self.unresolved_conditions:
            if condition.observation_ref is not None and condition.observation_ref not in index:
                raise ValueError("unresolved observation reference missing")
        if len(canonical_json_bytes(self.model_dump(mode="json"))) > 262144:
            raise ValueError("compact context exceeds 256 KiB")
        return self


def expected_unresolved_conditions(context: HardwareTriggerCandidateContext) -> tuple[UnresolvedCondition, ...]:
    """v1 inputs cannot authenticate run/build, client applicability or causality.

    Producer version and ISA model identity have no explicit authenticated fields
    in these inputs. This is a limitation of this context, not a global claim.
    """

    kinds = [U.NO_AUTHENTICATED_RUN_PROVENANCE, U.NO_AUTHENTICATED_BUILD_PROVENANCE,
             U.PROCESSORFUZZ_VERSION_UNKNOWN, U.ISA_MODEL_IDENTITY_UNKNOWN,
             U.CLIENT_APPLICABILITY_UNKNOWN, U.CAUSALITY_UNESTABLISHED,
             U.NECESSITY_UNESTABLISHED, U.SUFFICIENCY_UNESTABLISHED]
    if context.source.hardware_target.hardware_revision is None:
        kinds.append(U.HARDWARE_REVISION_UNKNOWN)
    result = [UnresolvedCondition(kind=k, alignment_scope_id=context.alignment_scope.id) for k in kinds]
    trace_by_id = {a.anchor_id: a for a in context.trace_anchors}
    anchored = {a.observation_id for a in context.trace_anchors}
    composed = {trace_by_id[a.trace_anchor_id].observation_id for a in context.composed_anchors}
    for pair in context.context_records:
        for kind, observation in ((K.ISA_OBSERVATION, pair.isa), (K.RTL_OBSERVATION, pair.rtl)):
            for missing, present in ((U.NO_DIRECT_SI_LABEL_ANCHOR, composed), (U.ELF_TRACE_ANCHOR_UNAVAILABLE, anchored)):
                if observation.observation_id not in present:
                    result.append(UnresolvedCondition(kind=missing, alignment_scope_id=context.alignment_scope.id,
                        observation_ref=ObjectiveFactReference(kind=kind, fact_id=observation.observation_id, owner_id=observation.source_id), pc=observation.pc))
    return tuple(sorted(result, key=lambda c: canonical_json_bytes(c.model_dump(mode="json"))))
