"""Source-bound observations and non-causal comparisons; no verification API."""

from chipchain.evidence.enums import ComparableField, ComparisonOutcome, EvidenceLevel, TraceSourceSide
from chipchain.evidence.models import EvidenceArtifactSource, FormatProfile, ParsedCaseArtifact
from chipchain.evidence.observations import (
    CaseObservation, IsaCsvObservation, IsaLogObservation,
    RtlDelayedObservation, RtlInstructionObservation, SignatureObservation,
)
from chipchain.evidence.alignment import (
    AlignedPair, AlignmentResult, AlignmentScope, DivergenceObservation, FieldComparison,
    align_common_program, divergence_context, first_observed_divergence_in_scope,
)

__all__ = [
    "ComparableField", "ComparisonOutcome", "EvidenceLevel", "TraceSourceSide",
    "EvidenceArtifactSource", "FormatProfile", "ParsedCaseArtifact", "CaseObservation",
    "IsaCsvObservation", "IsaLogObservation", "RtlDelayedObservation",
    "RtlInstructionObservation", "SignatureObservation", "AlignedPair", "AlignmentResult",
    "AlignmentScope", "DivergenceObservation", "FieldComparison", "align_common_program",
    "divergence_context", "first_observed_divergence_in_scope",
]
