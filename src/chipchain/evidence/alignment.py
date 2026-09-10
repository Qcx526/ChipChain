"""Deterministic contiguous key alignment and non-causal scoped comparisons."""

from typing import Literal, Self

from pydantic import model_validator

from chipchain.core import Identifier, ProgramAddress
from chipchain.behavior.processor import ExactScalar
from chipchain.evidence.base import EvidenceModel, Ordinal
from chipchain.evidence.enums import ComparableField, ComparisonOutcome, EvidenceLevel
from chipchain.evidence.models import EvidenceArtifactSource, ParsedCaseArtifact
from chipchain.evidence.observations import IsaCsvObservation, RtlInstructionObservation


class AlignmentScope(EvidenceModel):
    """Explicit byte sources, common start and approved field set; not a run ID."""

    _namespace = "v2-case-alignment-scope-v1"
    isa_source: EvidenceArtifactSource
    rtl_source: EvidenceArtifactSource
    common_start_pc: ProgramAddress
    comparable_fields: tuple[ComparableField, ...]
    alignment_profile_id: Literal["confirmed_common_sequence_v1"] = "confirmed_common_sequence_v1"
    run_provenance: Literal["CORRELATED_ARTIFACT_SET"] = "CORRELATED_ARTIFACT_SET"

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if self.isa_source.format_profile_id != "confirmed_isa_csv_v1" or self.rtl_source.format_profile_id != "confirmed_rocket_rtl_log_v1":
            raise ValueError("alignment requires confirmed ISA CSV and RTL log sources")
        if self.isa_source.architecture != self.rtl_source.architecture:
            raise ValueError("cross-architecture alignment is forbidden")
        if not self.comparable_fields or len(set(self.comparable_fields)) != len(self.comparable_fields):
            raise ValueError("comparison scope must be nonempty and duplicate-free")
        # Canonical set order also fixes which field is returned first at one pair.
        expected = tuple(field for field in ComparableField if field in self.comparable_fields)
        if self.comparable_fields != expected:
            raise ValueError("comparison fields must follow declared vocabulary order")
        return self


def _comparison(left: ExactScalar | None, right: ExactScalar | None) -> tuple[ComparisonOutcome, ExactScalar | None]:
    if left is None and right is None:
        return ComparisonOutcome.NOT_COMPARABLE, None
    if left is None:
        return ComparisonOutcome.MISSING_LEFT, None
    if right is None:
        return ComparisonOutcome.MISSING_RIGHT, None
    if left.width_bits != right.width_bits:
        return ComparisonOutcome.NOT_COMPARABLE, None
    if left.value == right.value:
        return ComparisonOutcome.EQUAL, None
    return ComparisonOutcome.DIFFERENT, ExactScalar(width_bits=left.width_bits, value=hex(int(left.value, 16) ^ int(right.value, 16)))


class FieldComparison(EvidenceModel):
    """Exact printed-value comparison, not bug/failure/verification status."""

    _namespace = "v2-case-field-comparison-v1"
    field: ComparableField
    isa_value: ExactScalar | None
    rtl_value: ExactScalar | None
    outcome: ComparisonOutcome
    xor: ExactScalar | None = None

    @classmethod
    def create(cls, field: ComparableField, isa_value: ExactScalar | None, rtl_value: ExactScalar | None) -> Self:
        """Compare detached exact values; missing values are never made zero."""

        left = ExactScalar.model_validate(isa_value) if isa_value is not None else None
        right = ExactScalar.model_validate(rtl_value) if rtl_value is not None else None
        outcome, xor = _comparison(left, right)
        return cls(field=field, isa_value=left, rtl_value=right, outcome=outcome, xor=xor)

    @model_validator(mode="after")
    def validate_comparison(self) -> Self:
        if (self.outcome, self.xor) != _comparison(self.isa_value, self.rtl_value):
            raise ValueError("field comparison does not match exact values/widths")
        return self


class AlignedPair(EvidenceModel):
    """Ordered pair retains both source-bound observations and approved comparisons."""

    _namespace = "v2-case-aligned-pair-v1"
    scope: AlignmentScope
    alignment_ordinal: Ordinal
    isa_observation: IsaCsvObservation
    rtl_observation: RtlInstructionObservation
    comparisons: tuple[FieldComparison, ...]

    @property
    def isa_observation_id(self) -> str:
        return self.isa_observation.id

    @property
    def rtl_observation_id(self) -> str:
        return self.rtl_observation.id

    @property
    def pc(self) -> ProgramAddress:
        return self.isa_observation.pc

    @property
    def instruction_encoding(self) -> str:
        return self.isa_observation.instruction_encoding

    @model_validator(mode="after")
    def validate_pair(self) -> Self:
        left, right = self.isa_observation, self.rtl_observation
        if left.source_id != self.scope.isa_source.id or right.source_id != self.scope.rtl_source.id:
            raise ValueError("pair source binding mismatch")
        if (left.pc, left.instruction_encoding) != (right.pc, right.instruction_encoding):
            raise ValueError("pair PC/encoding mismatch")
        expected = tuple(FieldComparison.create(field, left.state_value(field), right.state_value(field)) for field in self.scope.comparable_fields)
        if self.comparisons != expected:
            raise ValueError("pair comparisons differ from approved source fields")
        return self


def _instruction_key(item: IsaCsvObservation | RtlInstructionObservation) -> tuple[str, str]:
    return item.pc.value, item.instruction_encoding


def _select_pairs(
    scope: AlignmentScope, isa: ParsedCaseArtifact, rtl: ParsedCaseArtifact,
) -> tuple[tuple[IsaCsvObservation, RtlInstructionObservation], ...]:
    if scope.isa_source != isa.source or scope.rtl_source != rtl.source:
        raise ValueError("alignment sources differ from supplied exact artifacts")
    left = tuple(item for item in isa.observations if isinstance(item, IsaCsvObservation))
    right = tuple(item for item in rtl.observations if isinstance(item, RtlInstructionObservation))
    if not left or left[0].pc != scope.common_start_pc:
        raise ValueError("ISA sequence must start at the explicitly declared common PC")
    starts = [index for index, item in enumerate(right) if _instruction_key(item) == _instruction_key(left[0])]
    if len(starts) != 1:
        raise ValueError("common start key is missing or ambiguous")
    selected = right[starts[0]:starts[0] + len(left)]
    if len(selected) != len(left) or any(_instruction_key(a) != _instruction_key(b) for a, b in zip(left, selected, strict=True)):
        raise ValueError("common sequence is not contiguous with exact PC/encoding keys")
    # DELAYED remains an independent record; never guess its instruction owner.
    return tuple(zip(left, selected, strict=True))


class AlignmentResult(EvidenceModel):
    """Revalidatable full source snapshots plus a reproducible partial-semantic view."""

    _namespace = "v2-case-alignment-result-v1"
    contract: Literal["v2_case_alignment_result_v1"] = "v2_case_alignment_result_v1"
    scope: AlignmentScope
    isa_artifact: ParsedCaseArtifact
    rtl_artifact: ParsedCaseArtifact
    aligned_pairs: tuple[AlignedPair, ...]
    unaligned_isa_observation_ids: tuple[Identifier, ...]
    unaligned_rtl_observation_ids: tuple[Identifier, ...]
    status: Literal["RELIABLE_KEYS_PARTIAL_SEMANTICS"] = "RELIABLE_KEYS_PARTIAL_SEMANTICS"

    @model_validator(mode="after")
    def validate_reproduction(self) -> Self:
        selected = _select_pairs(self.scope, self.isa_artifact, self.rtl_artifact)
        if len(self.aligned_pairs) != len(selected):
            raise ValueError("alignment pair count differs from contiguous source sequence")
        for ordinal, (pair, (left, right)) in enumerate(zip(self.aligned_pairs, selected, strict=True)):
            if pair.scope != self.scope or pair.alignment_ordinal != ordinal or pair.isa_observation != left or pair.rtl_observation != right:
                raise ValueError("alignment pair is not the selected source occurrence")
        paired_right = {right.id for _, right in selected}
        expected_right = tuple(item.id for item in self.rtl_artifact.observations if item.id not in paired_right)
        if self.unaligned_isa_observation_ids or self.unaligned_rtl_observation_ids != expected_right:
            raise ValueError("unaligned records must preserve all remaining source occurrences")
        return self


def align_common_program(
    scope: AlignmentScope, isa_artifact: ParsedCaseArtifact, rtl_artifact: ParsedCaseArtifact,
) -> AlignmentResult:
    """Fail closed unless exact keys follow one contiguous common sequence."""

    scope = AlignmentScope.model_validate(scope)
    isa = ParsedCaseArtifact.model_validate(isa_artifact)
    rtl = ParsedCaseArtifact.model_validate(rtl_artifact)
    selected = _select_pairs(scope, isa, rtl)
    pairs = tuple(AlignedPair(
        scope=scope, alignment_ordinal=index, isa_observation=left, rtl_observation=right,
        comparisons=tuple(FieldComparison.create(field, left.state_value(field), right.state_value(field)) for field in scope.comparable_fields),
    ) for index, (left, right) in enumerate(selected))
    paired_right = {right.id for _, right in selected}
    return AlignmentResult(
        scope=scope, isa_artifact=isa, rtl_artifact=rtl, aligned_pairs=pairs,
        unaligned_isa_observation_ids=(),
        unaligned_rtl_observation_ids=tuple(item.id for item in rtl.observations if item.id not in paired_right),
    )


class DivergenceObservation(EvidenceModel):
    """A difference in one explicitly scoped pair, not a cause or trigger."""

    _namespace = "v2-case-divergence-observation-v1"
    aligned_pair: AlignedPair
    field: ComparableField
    evidence_level: Literal[EvidenceLevel.CROSS_ARTIFACT_CORRELATED] = EvidenceLevel.CROSS_ARTIFACT_CORRELATED

    @model_validator(mode="after")
    def validate_difference(self) -> Self:
        if not any(item.field == self.field and item.outcome == ComparisonOutcome.DIFFERENT for item in self.aligned_pair.comparisons):
            raise ValueError("divergence requires an explicit DIFFERENT field comparison")
        return self

    @property
    def comparison(self) -> FieldComparison:
        return next(item for item in self.aligned_pair.comparisons if item.field == self.field)

    @property
    def scope(self) -> AlignmentScope:
        return self.aligned_pair.scope


def first_observed_divergence_in_scope(result: AlignmentResult) -> DivergenceObservation | None:
    """First differing pair/field in this scope only, not a global first error."""

    snapshot = AlignmentResult.model_validate(result)
    for pair in snapshot.aligned_pairs:
        for comparison in pair.comparisons:
            if comparison.outcome == ComparisonOutcome.DIFFERENT:
                return DivergenceObservation(aligned_pair=pair, field=comparison.field)
    return None


def divergence_context(
    result: AlignmentResult, observation: DivergenceObservation, *, before: int = 5, after: int = 3,
) -> tuple[AlignedPair, ...]:
    """Return neighboring aligned records, never a causal slice/trigger window."""

    if type(before) is not int or type(after) is not int or before < 0 or after < 0:
        raise ValueError("context bounds must be nonnegative integers")
    result = AlignmentResult.model_validate(result)
    observation = DivergenceObservation.model_validate(observation)
    index = observation.aligned_pair.alignment_ordinal
    if index >= len(result.aligned_pairs) or result.aligned_pairs[index] != observation.aligned_pair:
        raise ValueError("divergence is outside this alignment result")
    return result.aligned_pairs[max(0, index - before):index + after + 1]
