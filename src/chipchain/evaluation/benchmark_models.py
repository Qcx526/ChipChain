"""Deterministic Phase 10B benchmark aggregation contracts."""

from __future__ import annotations

from typing import Mapping

from pydantic import Field, ValidationError, field_validator, model_validator

from chipchain.evaluation.candidate import FinalizedCandidateRecord
from chipchain.evaluation.claim_binding_models import (
    ModelClaimBindingAssessment,
)
from chipchain.evaluation.enums import (
    BenchmarkCaseLabel,
    BenchmarkCaseRunDisposition,
    BenchmarkExecutionFailureCode,
    BenchmarkExecutionStage,
    ChainFeasibilityStatus,
    EvaluationMetricName,
    EvaluationScope,
    ModelClaimBindingStatus,
)
from chipchain.evaluation.feasibility_models import (
    ChainFeasibilityAssessment,
    _validate_failure_metadata,
)
from chipchain.evaluation.errors import BenchmarkEvaluationBindingError
from chipchain.evaluation.models import _canonical_hash
from chipchain.hardware_trigger.aggregation import (
    TriggerabilityAggregationResult,
)
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.models.enums import Architecture


PHASE10B_RUNNER_CONTRACT = "phase10b_benchmark_evaluation_v1"


def _normalize_ids(values: list[str], *, label: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
    return sorted(values)


def _validate_metadata(value: Metadata) -> Metadata:
    return _validate_failure_metadata(value)


def benchmark_case_execution_failure_id(
    *,
    benchmark_case_id: str,
    architecture: Architecture,
    stage: BenchmarkExecutionStage,
    failure_code: BenchmarkExecutionFailureCode,
) -> str:
    """Build pre-finalization failure identity without diagnostics or metadata."""

    return _canonical_hash(
        "benchmark-case-execution-failure",
        {
            "architecture": Architecture(architecture).value,
            "benchmark_case_id": benchmark_case_id,
            "failure_code": BenchmarkExecutionFailureCode(failure_code).value,
            "stage": BenchmarkExecutionStage(stage).value,
        },
    )


class BenchmarkCaseExecutionFailure(DomainModel):
    """Bounded failure before a FinalizedCandidateRecord exists."""

    id: Identifier
    benchmark_case_id: Identifier
    architecture: Architecture
    stage: BenchmarkExecutionStage
    failure_code: BenchmarkExecutionFailureCode
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "BenchmarkCaseExecutionFailure":
        if self.architecture is not Architecture.ARM:
            raise ValueError("Phase 10B execution failures support ARM only")
        expected = benchmark_case_execution_failure_id(
            benchmark_case_id=self.benchmark_case_id,
            architecture=self.architecture,
            stage=self.stage,
            failure_code=self.failure_code,
        )
        if self.id != expected:
            raise ValueError(
                "BenchmarkCaseExecutionFailure ID is not deterministic"
            )
        return self

    @classmethod
    def create(
        cls,
        *,
        benchmark_case_id: str,
        architecture: Architecture | str,
        stage: BenchmarkExecutionStage | str,
        failure_code: BenchmarkExecutionFailureCode | str,
        metadata: Metadata | None = None,
    ) -> "BenchmarkCaseExecutionFailure":
        """Create one path-neutral pre-candidate execution failure."""

        normalized_architecture = Architecture(architecture)
        normalized_stage = BenchmarkExecutionStage(stage)
        normalized_code = BenchmarkExecutionFailureCode(failure_code)
        identity = benchmark_case_execution_failure_id(
            benchmark_case_id=benchmark_case_id.strip(),
            architecture=normalized_architecture,
            stage=normalized_stage,
            failure_code=normalized_code,
        )
        return cls(
            id=identity,
            benchmark_case_id=benchmark_case_id,
            architecture=normalized_architecture,
            stage=normalized_stage,
            failure_code=normalized_code,
            metadata=metadata or {},
        )


def candidate_evaluation_bundle_id(
    *,
    candidate_id: str,
    claim_binding_assessment_id: str,
    chain_feasibility_assessment_id: str,
    triggerability_aggregation_id: str | None,
) -> str:
    """Bind one truth-neutral set of finalized candidate-side outputs."""

    return _canonical_hash(
        "candidate-evaluation-bundle",
        {
            "candidate_id": candidate_id,
            "chain_feasibility_assessment_id": (
                chain_feasibility_assessment_id
            ),
            "claim_binding_assessment_id": claim_binding_assessment_id,
            "triggerability_aggregation_id": triggerability_aggregation_id,
        },
    )


class CandidateEvaluationBundle(DomainModel):
    """Truth-neutral frozen outputs for one finalized candidate."""

    id: Identifier
    candidate: FinalizedCandidateRecord
    claim_binding: ModelClaimBindingAssessment
    feasibility: ChainFeasibilityAssessment
    triggerability: TriggerabilityAggregationResult | None = None
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("candidate")
    @classmethod
    def snapshot_candidate(
        cls, value: FinalizedCandidateRecord
    ) -> FinalizedCandidateRecord:
        return FinalizedCandidateRecord.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("claim_binding")
    @classmethod
    def snapshot_claim_binding(
        cls, value: ModelClaimBindingAssessment
    ) -> ModelClaimBindingAssessment:
        return ModelClaimBindingAssessment.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("feasibility")
    @classmethod
    def snapshot_feasibility(
        cls, value: ChainFeasibilityAssessment
    ) -> ChainFeasibilityAssessment:
        return ChainFeasibilityAssessment.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("triggerability")
    @classmethod
    def snapshot_triggerability(
        cls, value: TriggerabilityAggregationResult | None
    ) -> TriggerabilityAggregationResult | None:
        if value is None:
            return None
        return TriggerabilityAggregationResult.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_metadata(value)

    @model_validator(mode="after")
    def validate_bindings_and_identity(self) -> "CandidateEvaluationBundle":
        candidate = self.candidate
        binding = self.claim_binding
        feasibility = self.feasibility
        claim = candidate.model_authored_chain_claim
        expected_claim_id = claim.id if claim is not None else None
        expected_claim_type = claim.interaction_type if claim is not None else None
        if (
            binding.candidate_id,
            binding.benchmark_case_id,
            binding.architecture,
            binding.model_authored_chain_claim_id,
            binding.claimed_interaction_type,
            binding.candidate_interaction_id,
            binding.candidate_interaction_type,
        ) != (
            candidate.id,
            candidate.benchmark_case_id,
            candidate.architecture,
            expected_claim_id,
            expected_claim_type,
            candidate.cross_layer_interaction_id,
            candidate.interaction_type,
        ):
            raise ValueError("claim-binding assessment and candidate mismatch")
        if (
            feasibility.candidate_id,
            feasibility.benchmark_case_id,
            feasibility.architecture,
            feasibility.interaction_id,
            feasibility.interaction_type,
        ) != (
            candidate.id,
            candidate.benchmark_case_id,
            candidate.architecture,
            candidate.cross_layer_interaction_id,
            candidate.interaction_type,
        ):
            raise ValueError("feasibility assessment and candidate mismatch")
        trigger = self.triggerability
        if feasibility.triggerability_aggregation_id is None:
            if trigger is not None:
                raise ValueError(
                    "triggerability supplied for feasibility without triggerability"
                )
        else:
            if trigger is None:
                raise ValueError(
                    "feasibility triggerability requires its exact result"
                )
            if (
                trigger.id,
                trigger.status,
                trigger.architecture,
                trigger.artifact_id,
                trigger.artifact_sha256,
            ) != (
                feasibility.triggerability_aggregation_id,
                feasibility.triggerability_status,
                candidate.architecture,
                feasibility.artifact_id,
                feasibility.artifact_sha256,
            ):
                raise ValueError(
                    "triggerability result and feasibility assessment mismatch"
                )
        expected_id = candidate_evaluation_bundle_id(
            candidate_id=candidate.id,
            claim_binding_assessment_id=binding.id,
            chain_feasibility_assessment_id=feasibility.id,
            triggerability_aggregation_id=(
                trigger.id if trigger is not None else None
            ),
        )
        if self.id != expected_id:
            raise ValueError("CandidateEvaluationBundle ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        candidate: FinalizedCandidateRecord,
        claim_binding: ModelClaimBindingAssessment,
        feasibility: ChainFeasibilityAssessment,
        triggerability: TriggerabilityAggregationResult | None = None,
        metadata: Metadata | None = None,
    ) -> "CandidateEvaluationBundle":
        """Create and detached-revalidate one candidate-side bundle."""

        trigger_id = triggerability.id if triggerability is not None else None
        identity = candidate_evaluation_bundle_id(
            candidate_id=candidate.id,
            claim_binding_assessment_id=claim_binding.id,
            chain_feasibility_assessment_id=feasibility.id,
            triggerability_aggregation_id=trigger_id,
        )
        try:
            return cls(
                id=identity,
                candidate=candidate,
                claim_binding=claim_binding,
                feasibility=feasibility,
                triggerability=triggerability,
                metadata=metadata or {},
            )
        except ValidationError as exc:
            raise BenchmarkEvaluationBindingError(
                "candidate evaluation bundle inputs are not exactly bound"
            ) from exc


def benchmark_case_run_record_id(
    *,
    benchmark_case_id: str,
    architecture: Architecture,
    disposition: BenchmarkCaseRunDisposition,
    candidate_evaluation_bundle_id: str | None,
    execution_failure_id: str | None,
) -> str:
    """Build one-attempt case accounting identity."""

    return _canonical_hash(
        "benchmark-case-run",
        {
            "architecture": Architecture(architecture).value,
            "benchmark_case_id": benchmark_case_id,
            "candidate_evaluation_bundle_id": candidate_evaluation_bundle_id,
            "disposition": BenchmarkCaseRunDisposition(disposition).value,
            "execution_failure_id": execution_failure_id,
        },
    )


class BenchmarkCaseRunRecord(DomainModel):
    """Exactly one explicit accounting record for one manifest case."""

    id: Identifier
    benchmark_case_id: Identifier
    architecture: Architecture
    disposition: BenchmarkCaseRunDisposition
    candidate_bundle: CandidateEvaluationBundle | None = None
    execution_failure: BenchmarkCaseExecutionFailure | None = None
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("candidate_bundle")
    @classmethod
    def snapshot_bundle(
        cls, value: CandidateEvaluationBundle | None
    ) -> CandidateEvaluationBundle | None:
        if value is None:
            return None
        return CandidateEvaluationBundle.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("execution_failure")
    @classmethod
    def snapshot_failure(
        cls, value: BenchmarkCaseExecutionFailure | None
    ) -> BenchmarkCaseExecutionFailure | None:
        if value is None:
            return None
        return BenchmarkCaseExecutionFailure.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_metadata(value)

    @model_validator(mode="after")
    def validate_shape_and_identity(self) -> "BenchmarkCaseRunRecord":
        if self.architecture is not Architecture.ARM:
            raise ValueError("Phase 10B case runs support ARM only")
        bundle_id: str | None = None
        failure_id: str | None = None
        if self.disposition is BenchmarkCaseRunDisposition.CANDIDATE:
            if self.candidate_bundle is None or self.execution_failure is not None:
                raise ValueError("candidate case run requires only a bundle")
            bundle_id = self.candidate_bundle.id
            candidate = self.candidate_bundle.candidate
            if (
                candidate.benchmark_case_id,
                candidate.architecture,
            ) != (self.benchmark_case_id, self.architecture):
                raise ValueError("candidate case-run binding mismatch")
        elif self.disposition is BenchmarkCaseRunDisposition.EXECUTION_FAILURE:
            if self.execution_failure is None or self.candidate_bundle is not None:
                raise ValueError("failed case run requires only a failure")
            failure_id = self.execution_failure.id
            if (
                self.execution_failure.benchmark_case_id,
                self.execution_failure.architecture,
            ) != (self.benchmark_case_id, self.architecture):
                raise ValueError("execution-failure case-run binding mismatch")
        elif self.candidate_bundle is not None or self.execution_failure is not None:
            raise ValueError("predeclared exclusion cannot contain run outputs")
        expected = benchmark_case_run_record_id(
            benchmark_case_id=self.benchmark_case_id,
            architecture=self.architecture,
            disposition=self.disposition,
            candidate_evaluation_bundle_id=bundle_id,
            execution_failure_id=failure_id,
        )
        if self.id != expected:
            raise ValueError("BenchmarkCaseRunRecord ID is not deterministic")
        return self

    @classmethod
    def from_candidate(
        cls,
        bundle: CandidateEvaluationBundle,
        *,
        metadata: Metadata | None = None,
    ) -> "BenchmarkCaseRunRecord":
        """Account for one case that produced a finalized candidate."""

        candidate = bundle.candidate
        identity = benchmark_case_run_record_id(
            benchmark_case_id=candidate.benchmark_case_id,
            architecture=candidate.architecture,
            disposition=BenchmarkCaseRunDisposition.CANDIDATE,
            candidate_evaluation_bundle_id=bundle.id,
            execution_failure_id=None,
        )
        return cls(
            id=identity,
            benchmark_case_id=candidate.benchmark_case_id,
            architecture=candidate.architecture,
            disposition=BenchmarkCaseRunDisposition.CANDIDATE,
            candidate_bundle=bundle,
            metadata=metadata or {},
        )

    @classmethod
    def from_execution_failure(
        cls,
        failure: BenchmarkCaseExecutionFailure,
        *,
        metadata: Metadata | None = None,
    ) -> "BenchmarkCaseRunRecord":
        """Account for one case that failed before candidate finalization."""

        identity = benchmark_case_run_record_id(
            benchmark_case_id=failure.benchmark_case_id,
            architecture=failure.architecture,
            disposition=BenchmarkCaseRunDisposition.EXECUTION_FAILURE,
            candidate_evaluation_bundle_id=None,
            execution_failure_id=failure.id,
        )
        return cls(
            id=identity,
            benchmark_case_id=failure.benchmark_case_id,
            architecture=failure.architecture,
            disposition=BenchmarkCaseRunDisposition.EXECUTION_FAILURE,
            execution_failure=failure,
            metadata=metadata or {},
        )

    @classmethod
    def predeclared_excluded(
        cls,
        *,
        benchmark_case_id: str,
        architecture: Architecture | str,
        metadata: Metadata | None = None,
    ) -> "BenchmarkCaseRunRecord":
        """Account for a case whose manifest scope was already excluded."""

        normalized_architecture = Architecture(architecture)
        identity = benchmark_case_run_record_id(
            benchmark_case_id=benchmark_case_id.strip(),
            architecture=normalized_architecture,
            disposition=BenchmarkCaseRunDisposition.PREDECLARED_EXCLUDED,
            candidate_evaluation_bundle_id=None,
            execution_failure_id=None,
        )
        return cls(
            id=identity,
            benchmark_case_id=benchmark_case_id,
            architecture=normalized_architecture,
            disposition=BenchmarkCaseRunDisposition.PREDECLARED_EXCLUDED,
            metadata=metadata or {},
        )


def benchmark_candidate_assessment_id(
    *,
    benchmark_manifest_id: str,
    benchmark_case_id: str,
    candidate_id: str,
    architecture: Architecture,
    evaluation_scope: EvaluationScope,
    case_label: BenchmarkCaseLabel,
    claim_binding_assessment_id: str,
    claim_binding_status: ModelClaimBindingStatus,
    chain_feasibility_assessment_id: str,
    chain_feasibility_status: ChainFeasibilityStatus,
    matched_ground_truth_chain_ids: list[str],
    strict_hit: bool,
    negative_control_false_positive: bool,
) -> str:
    """Build benchmark-relative candidate result identity."""

    return _canonical_hash(
        "benchmark-candidate-assessment",
        {
            "architecture": Architecture(architecture).value,
            "benchmark_case_id": benchmark_case_id,
            "benchmark_manifest_id": benchmark_manifest_id,
            "candidate_id": candidate_id,
            "case_label": BenchmarkCaseLabel(case_label).value,
            "chain_feasibility_assessment_id": (
                chain_feasibility_assessment_id
            ),
            "chain_feasibility_status": ChainFeasibilityStatus(
                chain_feasibility_status
            ).value,
            "claim_binding_assessment_id": claim_binding_assessment_id,
            "claim_binding_status": ModelClaimBindingStatus(
                claim_binding_status
            ).value,
            "evaluation_scope": EvaluationScope(evaluation_scope).value,
            "matched_ground_truth_chain_ids": sorted(
                matched_ground_truth_chain_ids
            ),
            "negative_control_false_positive": (
                negative_control_false_positive
            ),
            "strict_hit": strict_hit,
        },
    )


class BenchmarkCandidateAssessment(DomainModel):
    """First candidate result allowed to compare frozen outputs with Ground Truth."""

    id: Identifier
    benchmark_manifest_id: Identifier
    benchmark_case_id: Identifier
    candidate_id: Identifier
    architecture: Architecture
    evaluation_scope: EvaluationScope
    case_label: BenchmarkCaseLabel
    claim_binding_assessment_id: Identifier
    claim_binding_status: ModelClaimBindingStatus
    chain_feasibility_assessment_id: Identifier
    chain_feasibility_status: ChainFeasibilityStatus
    matched_ground_truth_chain_ids: list[Identifier] = Field(default_factory=list)
    strict_hit: bool
    negative_control_false_positive: bool
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("matched_ground_truth_chain_ids")
    @classmethod
    def normalize_matches(cls, values: list[str]) -> list[str]:
        return _normalize_ids(values, label="matched Ground Truth chain IDs")

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_metadata(value)

    @model_validator(mode="after")
    def validate_derived_outcomes_and_identity(
        self,
    ) -> "BenchmarkCandidateAssessment":
        if self.architecture is not Architecture.ARM:
            raise ValueError("Phase 10B candidate assessments support ARM only")
        prerequisite = (
            self.claim_binding_status is ModelClaimBindingStatus.ALIGNED
            and self.chain_feasibility_status
            is ChainFeasibilityStatus.CONFIRMED_FEASIBLE
        )
        expected_hit = (
            self.evaluation_scope is EvaluationScope.PRIMARY_TARGET
            and self.case_label is BenchmarkCaseLabel.POSITIVE_FEASIBLE
            and prerequisite
            and bool(self.matched_ground_truth_chain_ids)
        )
        expected_false_positive = (
            self.evaluation_scope is EvaluationScope.PRIMARY_TARGET
            and self.case_label is BenchmarkCaseLabel.NEGATIVE_CONTROL
            and prerequisite
        )
        if self.strict_hit is not expected_hit:
            raise ValueError("strict hit is not derived from benchmark semantics")
        if self.negative_control_false_positive is not expected_false_positive:
            raise ValueError(
                "negative-control false positive is not derived from semantics"
            )
        if self.matched_ground_truth_chain_ids and not prerequisite:
            raise ValueError(
                "Ground Truth matches require strict candidate prerequisites"
            )
        if (
            self.case_label is BenchmarkCaseLabel.NEGATIVE_CONTROL
            and self.matched_ground_truth_chain_ids
        ):
            raise ValueError("negative controls cannot match Ground Truth chains")
        expected = benchmark_candidate_assessment_id(
            benchmark_manifest_id=self.benchmark_manifest_id,
            benchmark_case_id=self.benchmark_case_id,
            candidate_id=self.candidate_id,
            architecture=self.architecture,
            evaluation_scope=self.evaluation_scope,
            case_label=self.case_label,
            claim_binding_assessment_id=self.claim_binding_assessment_id,
            claim_binding_status=self.claim_binding_status,
            chain_feasibility_assessment_id=(
                self.chain_feasibility_assessment_id
            ),
            chain_feasibility_status=self.chain_feasibility_status,
            matched_ground_truth_chain_ids=self.matched_ground_truth_chain_ids,
            strict_hit=self.strict_hit,
            negative_control_false_positive=(
                self.negative_control_false_positive
            ),
        )
        if self.id != expected:
            raise ValueError("BenchmarkCandidateAssessment ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        benchmark_manifest_id: str,
        benchmark_case_id: str,
        candidate_id: str,
        architecture: Architecture,
        evaluation_scope: EvaluationScope,
        case_label: BenchmarkCaseLabel,
        claim_binding_assessment_id: str,
        claim_binding_status: ModelClaimBindingStatus,
        chain_feasibility_assessment_id: str,
        chain_feasibility_status: ChainFeasibilityStatus,
        matched_ground_truth_chain_ids: list[str],
        metadata: Metadata | None = None,
    ) -> "BenchmarkCandidateAssessment":
        """Derive benchmark hit/false-positive flags from frozen statuses."""

        matches = sorted(matched_ground_truth_chain_ids)
        prerequisite = (
            claim_binding_status is ModelClaimBindingStatus.ALIGNED
            and chain_feasibility_status
            is ChainFeasibilityStatus.CONFIRMED_FEASIBLE
        )
        strict_hit = (
            evaluation_scope is EvaluationScope.PRIMARY_TARGET
            and case_label is BenchmarkCaseLabel.POSITIVE_FEASIBLE
            and prerequisite
            and bool(matches)
        )
        false_positive = (
            evaluation_scope is EvaluationScope.PRIMARY_TARGET
            and case_label is BenchmarkCaseLabel.NEGATIVE_CONTROL
            and prerequisite
        )
        identity = benchmark_candidate_assessment_id(
            benchmark_manifest_id=benchmark_manifest_id,
            benchmark_case_id=benchmark_case_id,
            candidate_id=candidate_id,
            architecture=architecture,
            evaluation_scope=evaluation_scope,
            case_label=case_label,
            claim_binding_assessment_id=claim_binding_assessment_id,
            claim_binding_status=claim_binding_status,
            chain_feasibility_assessment_id=chain_feasibility_assessment_id,
            chain_feasibility_status=chain_feasibility_status,
            matched_ground_truth_chain_ids=matches,
            strict_hit=strict_hit,
            negative_control_false_positive=false_positive,
        )
        return cls(
            id=identity,
            benchmark_manifest_id=benchmark_manifest_id,
            benchmark_case_id=benchmark_case_id,
            candidate_id=candidate_id,
            architecture=architecture,
            evaluation_scope=evaluation_scope,
            case_label=case_label,
            claim_binding_assessment_id=claim_binding_assessment_id,
            claim_binding_status=claim_binding_status,
            chain_feasibility_assessment_id=chain_feasibility_assessment_id,
            chain_feasibility_status=chain_feasibility_status,
            matched_ground_truth_chain_ids=matches,
            strict_hit=strict_hit,
            negative_control_false_positive=false_positive,
            metadata=metadata or {},
        )


def ground_truth_recovery_record_id(
    *,
    benchmark_manifest_id: str,
    benchmark_case_id: str,
    ground_truth_chain_id: str,
    evaluation_scope: EvaluationScope,
    case_label: BenchmarkCaseLabel,
    recovered_candidate_ids: list[str],
) -> str:
    """Build one per-chain recovery identity from exact candidate matches."""

    return _canonical_hash(
        "ground-truth-recovery",
        {
            "benchmark_case_id": benchmark_case_id,
            "benchmark_manifest_id": benchmark_manifest_id,
            "case_label": BenchmarkCaseLabel(case_label).value,
            "evaluation_scope": EvaluationScope(evaluation_scope).value,
            "ground_truth_chain_id": ground_truth_chain_id,
            "recovered_candidate_ids": sorted(recovered_candidate_ids),
        },
    )


class GroundTruthRecoveryRecord(DomainModel):
    """Immutable accounting for exact recovery of one declared Ground Truth chain."""

    id: Identifier
    benchmark_manifest_id: Identifier
    benchmark_case_id: Identifier
    ground_truth_chain_id: Identifier
    evaluation_scope: EvaluationScope
    case_label: BenchmarkCaseLabel
    recovered_candidate_ids: list[Identifier] = Field(default_factory=list)
    recovered: bool
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("recovered_candidate_ids")
    @classmethod
    def normalize_candidates(cls, values: list[str]) -> list[str]:
        return _normalize_ids(values, label="recovered candidate IDs")

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_metadata(value)

    @model_validator(mode="after")
    def validate_recovery_and_identity(self) -> "GroundTruthRecoveryRecord":
        if self.case_label is not BenchmarkCaseLabel.POSITIVE_FEASIBLE:
            raise ValueError("only positive cases may declare Ground Truth recovery")
        if self.recovered is not bool(self.recovered_candidate_ids):
            raise ValueError("Ground Truth recovery flag is not derived")
        expected = ground_truth_recovery_record_id(
            benchmark_manifest_id=self.benchmark_manifest_id,
            benchmark_case_id=self.benchmark_case_id,
            ground_truth_chain_id=self.ground_truth_chain_id,
            evaluation_scope=self.evaluation_scope,
            case_label=self.case_label,
            recovered_candidate_ids=self.recovered_candidate_ids,
        )
        if self.id != expected:
            raise ValueError("GroundTruthRecoveryRecord ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        benchmark_manifest_id: str,
        benchmark_case_id: str,
        ground_truth_chain_id: str,
        evaluation_scope: EvaluationScope,
        case_label: BenchmarkCaseLabel,
        recovered_candidate_ids: list[str],
        metadata: Metadata | None = None,
    ) -> "GroundTruthRecoveryRecord":
        """Create one deterministic per-chain recovery record."""

        candidates = sorted(recovered_candidate_ids)
        identity = ground_truth_recovery_record_id(
            benchmark_manifest_id=benchmark_manifest_id,
            benchmark_case_id=benchmark_case_id,
            ground_truth_chain_id=ground_truth_chain_id,
            evaluation_scope=evaluation_scope,
            case_label=case_label,
            recovered_candidate_ids=candidates,
        )
        return cls(
            id=identity,
            benchmark_manifest_id=benchmark_manifest_id,
            benchmark_case_id=benchmark_case_id,
            ground_truth_chain_id=ground_truth_chain_id,
            evaluation_scope=evaluation_scope,
            case_label=case_label,
            recovered_candidate_ids=candidates,
            recovered=bool(candidates),
            metadata=metadata or {},
        )


def evaluation_metric_result_id(
    *,
    metric_name: EvaluationMetricName,
    numerator: int,
    denominator: int,
    numerator_ids: list[str],
    denominator_ids: list[str],
    defined: bool,
) -> str:
    """Build rational metric identity without rounded float values."""

    return _canonical_hash(
        "evaluation-metric-result",
        {
            "defined": defined,
            "denominator": denominator,
            "denominator_ids": sorted(denominator_ids),
            "metric_name": EvaluationMetricName(metric_name).value,
            "numerator": numerator,
            "numerator_ids": sorted(numerator_ids),
        },
    )


class EvaluationMetricResult(DomainModel):
    """Exact cohort-based rational metric with explicit undefined state."""

    id: Identifier
    metric_name: EvaluationMetricName
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    numerator_ids: list[Identifier] = Field(default_factory=list)
    denominator_ids: list[Identifier] = Field(default_factory=list)
    defined: bool
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("numerator_ids")
    @classmethod
    def normalize_numerator_ids(cls, values: list[str]) -> list[str]:
        return _normalize_ids(values, label="metric numerator IDs")

    @field_validator("denominator_ids")
    @classmethod
    def normalize_denominator_ids(cls, values: list[str]) -> list[str]:
        return _normalize_ids(values, label="metric denominator IDs")

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_metadata(value)

    @model_validator(mode="after")
    def validate_cohorts_and_identity(self) -> "EvaluationMetricResult":
        if self.numerator != len(self.numerator_ids):
            raise ValueError("metric numerator does not match its exact cohort")
        if self.denominator != len(self.denominator_ids):
            raise ValueError("metric denominator does not match its exact cohort")
        if not set(self.numerator_ids).issubset(self.denominator_ids):
            raise ValueError("metric numerator cohort must be a denominator subset")
        if self.numerator > self.denominator:
            raise ValueError("metric numerator cannot exceed denominator")
        if self.defined is not (self.denominator > 0):
            raise ValueError("metric defined flag is not denominator-derived")
        expected = evaluation_metric_result_id(
            metric_name=self.metric_name,
            numerator=self.numerator,
            denominator=self.denominator,
            numerator_ids=self.numerator_ids,
            denominator_ids=self.denominator_ids,
            defined=self.defined,
        )
        if self.id != expected:
            raise ValueError("EvaluationMetricResult ID is not deterministic")
        return self

    @property
    def ratio(self) -> float | None:
        """Return an unrounded convenience ratio, or None when undefined."""

        if not self.defined:
            return None
        return self.numerator / self.denominator

    @property
    def percentage(self) -> float | None:
        """Return a convenience percentage excluded from identity."""

        ratio = self.ratio
        return ratio * 100.0 if ratio is not None else None

    @classmethod
    def create(
        cls,
        *,
        metric_name: EvaluationMetricName | str,
        numerator_ids: list[str],
        denominator_ids: list[str],
        metadata: Metadata | None = None,
    ) -> "EvaluationMetricResult":
        """Derive exact counts and defined state from supplied cohorts."""

        metric = EvaluationMetricName(metric_name)
        numerator_values = sorted(numerator_ids)
        denominator_values = sorted(denominator_ids)
        numerator = len(numerator_values)
        denominator = len(denominator_values)
        defined = denominator > 0
        identity = evaluation_metric_result_id(
            metric_name=metric,
            numerator=numerator,
            denominator=denominator,
            numerator_ids=numerator_values,
            denominator_ids=denominator_values,
            defined=defined,
        )
        return cls(
            id=identity,
            metric_name=metric,
            numerator=numerator,
            denominator=denominator,
            numerator_ids=numerator_values,
            denominator_ids=denominator_values,
            defined=defined,
            metadata=metadata or {},
        )


def benchmark_evaluation_report_id(
    *,
    runner_contract: str,
    benchmark_manifest_id: str,
    benchmark_version: str,
    case_run_record_ids: list[str],
    candidate_assessment_ids: list[str],
    ground_truth_recovery_ids: list[str],
    metric_result_ids: list[str],
    primary_scope_complete: bool,
    claim_binding_status_counts: Mapping[ModelClaimBindingStatus, int],
    feasibility_status_counts: Mapping[ChainFeasibilityStatus, int],
) -> str:
    """Build top-level report identity from exact aggregate cohorts."""

    return _canonical_hash(
        "benchmark-evaluation-report",
        {
            "benchmark_manifest_id": benchmark_manifest_id,
            "benchmark_version": benchmark_version,
            "candidate_assessment_ids": sorted(candidate_assessment_ids),
            "case_run_record_ids": sorted(case_run_record_ids),
            "claim_binding_status_counts": {
                status.value: claim_binding_status_counts[status]
                for status in ModelClaimBindingStatus
            },
            "feasibility_status_counts": {
                status.value: feasibility_status_counts[status]
                for status in ChainFeasibilityStatus
            },
            "ground_truth_recovery_ids": sorted(ground_truth_recovery_ids),
            "metric_result_ids": sorted(metric_result_ids),
            "primary_scope_complete": primary_scope_complete,
            "runner_contract": runner_contract,
        },
    )


class BenchmarkEvaluationReport(DomainModel):
    """Deterministic manifest-level Phase 10B result."""

    id: Identifier
    runner_contract: Identifier
    benchmark_manifest_id: Identifier
    benchmark_version: Identifier
    case_run_record_ids: list[Identifier]
    candidate_assessments: list[BenchmarkCandidateAssessment]
    ground_truth_recoveries: list[GroundTruthRecoveryRecord]
    verification_hit_rate: EvaluationMetricResult
    ground_truth_chain_recall: EvaluationMetricResult
    negative_control_false_positive_rate: EvaluationMetricResult
    primary_case_coverage: EvaluationMetricResult
    primary_scope_complete: bool
    claim_binding_status_counts: dict[ModelClaimBindingStatus, int]
    feasibility_status_counts: dict[ChainFeasibilityStatus, int]
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("case_run_record_ids")
    @classmethod
    def normalize_case_runs(cls, values: list[str]) -> list[str]:
        return _normalize_ids(values, label="case-run record IDs")

    @field_validator("candidate_assessments")
    @classmethod
    def normalize_assessments(
        cls, values: list[BenchmarkCandidateAssessment]
    ) -> list[BenchmarkCandidateAssessment]:
        if len(values) != len({item.id for item in values}):
            raise ValueError("candidate assessment IDs must be unique")
        return sorted(values, key=lambda item: item.id)

    @field_validator("ground_truth_recoveries")
    @classmethod
    def normalize_recoveries(
        cls, values: list[GroundTruthRecoveryRecord]
    ) -> list[GroundTruthRecoveryRecord]:
        if len(values) != len({item.id for item in values}):
            raise ValueError("Ground Truth recovery IDs must be unique")
        return sorted(values, key=lambda item: item.id)

    @field_validator("claim_binding_status_counts")
    @classmethod
    def validate_claim_counts(
        cls, values: dict[ModelClaimBindingStatus, int]
    ) -> dict[ModelClaimBindingStatus, int]:
        if set(values) != set(ModelClaimBindingStatus):
            raise ValueError("claim-binding counts must include every status")
        if any(value < 0 for value in values.values()):
            raise ValueError("claim-binding counts cannot be negative")
        return values

    @field_validator("feasibility_status_counts")
    @classmethod
    def validate_feasibility_counts(
        cls, values: dict[ChainFeasibilityStatus, int]
    ) -> dict[ChainFeasibilityStatus, int]:
        if set(values) != set(ChainFeasibilityStatus):
            raise ValueError("feasibility counts must include every status")
        if any(value < 0 for value in values.values()):
            raise ValueError("feasibility counts cannot be negative")
        return values

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_metadata(value)

    @model_validator(mode="after")
    def validate_derived_report_and_identity(self) -> "BenchmarkEvaluationReport":
        if self.runner_contract != PHASE10B_RUNNER_CONTRACT:
            raise ValueError("unsupported Phase 10B runner contract")
        metrics = (
            self.verification_hit_rate,
            self.ground_truth_chain_recall,
            self.negative_control_false_positive_rate,
            self.primary_case_coverage,
        )
        expected_names = (
            EvaluationMetricName.VERIFICATION_HIT_RATE,
            EvaluationMetricName.GROUND_TRUTH_CHAIN_RECALL,
            EvaluationMetricName.NEGATIVE_CONTROL_FALSE_POSITIVE_RATE,
            EvaluationMetricName.PRIMARY_CASE_COVERAGE,
        )
        if tuple(item.metric_name for item in metrics) != expected_names:
            raise ValueError("report metric contracts are inexact")
        if self.primary_scope_complete is not (
            self.primary_case_coverage.numerator
            == self.primary_case_coverage.denominator
        ):
            raise ValueError("primary scope completeness is not coverage-derived")
        if any(
            item.benchmark_manifest_id != self.benchmark_manifest_id
            for item in self.candidate_assessments
        ) or any(
            item.benchmark_manifest_id != self.benchmark_manifest_id
            for item in self.ground_truth_recoveries
        ):
            raise ValueError("report children belong to another manifest")
        if len(self.candidate_assessments) != len(
            {item.candidate_id for item in self.candidate_assessments}
        ) or len(self.candidate_assessments) != len(
            {item.benchmark_case_id for item in self.candidate_assessments}
        ):
            raise ValueError("report permits at most one candidate per case")
        if len(self.ground_truth_recoveries) != len(
            {
                item.ground_truth_chain_id
                for item in self.ground_truth_recoveries
            }
        ):
            raise ValueError("report Ground Truth recovery chains must be unique")
        for recovery in self.ground_truth_recoveries:
            expected_candidates = sorted(
                item.candidate_id
                for item in self.candidate_assessments
                if item.benchmark_case_id == recovery.benchmark_case_id
                and recovery.ground_truth_chain_id
                in item.matched_ground_truth_chain_ids
            )
            if recovery.recovered_candidate_ids != expected_candidates:
                raise ValueError("Ground Truth recovery cohort is not exact")
        primary = [
            item
            for item in self.candidate_assessments
            if item.evaluation_scope is EvaluationScope.PRIMARY_TARGET
        ]
        expected_claim_counts = {
            status: sum(item.claim_binding_status is status for item in primary)
            for status in ModelClaimBindingStatus
        }
        expected_feasibility_counts = {
            status: sum(
                item.chain_feasibility_status is status for item in primary
            )
            for status in ChainFeasibilityStatus
        }
        if self.claim_binding_status_counts != expected_claim_counts:
            raise ValueError("claim-binding status counts are not derived")
        if self.feasibility_status_counts != expected_feasibility_counts:
            raise ValueError("feasibility status counts are not derived")
        primary_candidate_ids = sorted(item.candidate_id for item in primary)
        strict_hit_ids = sorted(
            item.candidate_id for item in primary if item.strict_hit
        )
        if (
            self.verification_hit_rate.denominator_ids != primary_candidate_ids
            or self.verification_hit_rate.numerator_ids != strict_hit_ids
        ):
            raise ValueError("verification hit-rate cohorts are not exact")
        negative = [
            item
            for item in primary
            if item.case_label is BenchmarkCaseLabel.NEGATIVE_CONTROL
        ]
        if self.negative_control_false_positive_rate.denominator_ids != sorted(
            item.candidate_id for item in negative
        ) or self.negative_control_false_positive_rate.numerator_ids != sorted(
            item.candidate_id
            for item in negative
            if item.negative_control_false_positive
        ):
            raise ValueError("negative-control metric cohorts are not exact")
        primary_recoveries = [
            item
            for item in self.ground_truth_recoveries
            if item.evaluation_scope is EvaluationScope.PRIMARY_TARGET
            and item.case_label is BenchmarkCaseLabel.POSITIVE_FEASIBLE
        ]
        if self.ground_truth_chain_recall.denominator_ids != sorted(
            item.ground_truth_chain_id for item in primary_recoveries
        ) or self.ground_truth_chain_recall.numerator_ids != sorted(
            item.ground_truth_chain_id
            for item in primary_recoveries
            if item.recovered
        ):
            raise ValueError("Ground Truth recall cohorts are not exact")
        expected_id = benchmark_evaluation_report_id(
            runner_contract=self.runner_contract,
            benchmark_manifest_id=self.benchmark_manifest_id,
            benchmark_version=self.benchmark_version,
            case_run_record_ids=self.case_run_record_ids,
            candidate_assessment_ids=[
                item.id for item in self.candidate_assessments
            ],
            ground_truth_recovery_ids=[
                item.id for item in self.ground_truth_recoveries
            ],
            metric_result_ids=[item.id for item in metrics],
            primary_scope_complete=self.primary_scope_complete,
            claim_binding_status_counts=self.claim_binding_status_counts,
            feasibility_status_counts=self.feasibility_status_counts,
        )
        if self.id != expected_id:
            raise ValueError("BenchmarkEvaluationReport ID is not deterministic")
        return self
