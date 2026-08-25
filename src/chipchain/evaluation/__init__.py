"""Public Phase 10A benchmark and finalized-candidate contracts."""

from chipchain.evaluation.candidate import (
    FinalizedCandidateBuilder,
    FinalizedCandidateRecord,
    finalized_candidate_id,
)
from chipchain.evaluation.enums import (
    BenchmarkCaseLabel,
    BenchmarkSourceKind,
    ChainFeasibilityReason,
    ChainFeasibilityStatus,
    EvaluationScope,
    ObjectiveFailureStage,
    ModelClaimBindingReason,
    ModelClaimBindingStatus,
)
from chipchain.evaluation.errors import (
    ChainFeasibilityBindingError,
    EvaluationOracleError,
    InvalidChainFeasibilityInputError,
    InvalidModelClaimBindingInputError,
    ModelClaimBindingError,
)
from chipchain.evaluation.claim_binding import ModelClaimBinder
from chipchain.evaluation.claim_binding_models import (
    ModelClaimBindingAssessment,
    model_claim_binding_assessment_id,
)
from chipchain.evaluation.feasibility_models import (
    ChainFeasibilityAssessment,
    ObjectiveEvaluationFailure,
    chain_feasibility_assessment_id,
    objective_evaluation_failure_id,
)
from chipchain.evaluation.models import (
    BenchmarkArtifactReference,
    BenchmarkManifest,
    EvaluationBenchmarkCase,
    GroundTruthChain,
    benchmark_case_id,
    benchmark_manifest_id,
    ground_truth_chain_id,
)
from chipchain.evaluation.oracle import ChainFeasibilityOracle

__all__ = [
    "BenchmarkArtifactReference",
    "BenchmarkCaseLabel",
    "BenchmarkManifest",
    "BenchmarkSourceKind",
    "ChainFeasibilityAssessment",
    "ChainFeasibilityBindingError",
    "ChainFeasibilityOracle",
    "ChainFeasibilityReason",
    "ChainFeasibilityStatus",
    "EvaluationOracleError",
    "EvaluationBenchmarkCase",
    "EvaluationScope",
    "FinalizedCandidateBuilder",
    "FinalizedCandidateRecord",
    "GroundTruthChain",
    "InvalidChainFeasibilityInputError",
    "InvalidModelClaimBindingInputError",
    "ModelClaimBinder",
    "ModelClaimBindingAssessment",
    "ModelClaimBindingError",
    "ModelClaimBindingReason",
    "ModelClaimBindingStatus",
    "ObjectiveEvaluationFailure",
    "ObjectiveFailureStage",
    "benchmark_case_id",
    "benchmark_manifest_id",
    "chain_feasibility_assessment_id",
    "finalized_candidate_id",
    "ground_truth_chain_id",
    "objective_evaluation_failure_id",
    "model_claim_binding_assessment_id",
]
