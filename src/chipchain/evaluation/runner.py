"""Aggregation-only Phase 10B deterministic benchmark evaluation runner."""

from __future__ import annotations

from pydantic import ValidationError

from chipchain.evaluation.benchmark_models import (
    PHASE10B_RUNNER_CONTRACT,
    BenchmarkCandidateAssessment,
    BenchmarkCaseRunRecord,
    BenchmarkEvaluationReport,
    CandidateEvaluationBundle,
    EvaluationMetricResult,
    GroundTruthRecoveryRecord,
    benchmark_evaluation_report_id,
)
from chipchain.evaluation.enums import (
    BenchmarkCaseLabel,
    BenchmarkCaseRunDisposition,
    ChainFeasibilityStatus,
    EvaluationMetricName,
    EvaluationScope,
    ModelClaimBindingStatus,
)
from chipchain.evaluation.errors import (
    BenchmarkCaseAccountingError,
    BenchmarkEvaluationBindingError,
    InvalidBenchmarkEvaluationInputError,
)
from chipchain.evaluation.models import (
    BenchmarkManifest,
    EvaluationBenchmarkCase,
    GroundTruthChain,
)


class BenchmarkEvaluationRunner:
    """Compare finalized outputs with frozen Ground Truth and aggregate metrics."""

    contract = PHASE10B_RUNNER_CONTRACT

    def evaluate(
        self,
        manifest: BenchmarkManifest,
        case_run_records: list[BenchmarkCaseRunRecord],
    ) -> BenchmarkEvaluationReport:
        """Account for every case and derive deterministic benchmark outcomes."""

        detached_manifest = self._snapshot_manifest(manifest)
        runs = [self._snapshot_run(item) for item in case_run_records]
        run_by_case: dict[str, BenchmarkCaseRunRecord] = {}
        for run in runs:
            if run.benchmark_case_id in run_by_case:
                raise BenchmarkCaseAccountingError(
                    "duplicate benchmark case-run record"
                )
            run_by_case[run.benchmark_case_id] = run

        manifest_case_ids = {item.id for item in detached_manifest.cases}
        run_case_ids = set(run_by_case)
        missing = manifest_case_ids.difference(run_case_ids)
        extra = run_case_ids.difference(manifest_case_ids)
        if missing:
            raise BenchmarkCaseAccountingError(
                "benchmark manifest case-run record is missing"
            )
        if extra:
            raise BenchmarkCaseAccountingError(
                "case-run record is not present in benchmark manifest"
            )

        assessments: list[BenchmarkCandidateAssessment] = []
        for case in detached_manifest.cases:
            run = run_by_case[case.id]
            self._validate_case_run(case, run)
            if run.disposition is BenchmarkCaseRunDisposition.CANDIDATE:
                bundle = run.candidate_bundle
                if bundle is None:  # pragma: no cover - model enforces shape
                    raise InvalidBenchmarkEvaluationInputError(
                        "candidate case run lost its bundle"
                    )
                assessments.append(
                    self._assess_candidate(detached_manifest.id, case, bundle)
                )

        recoveries = self._ground_truth_recoveries(
            detached_manifest,
            assessments,
        )
        verification_hit_rate = EvaluationMetricResult.create(
            metric_name=EvaluationMetricName.VERIFICATION_HIT_RATE,
            numerator_ids=[
                item.candidate_id
                for item in assessments
                if item.evaluation_scope is EvaluationScope.PRIMARY_TARGET
                and item.strict_hit
            ],
            denominator_ids=[
                item.candidate_id
                for item in assessments
                if item.evaluation_scope is EvaluationScope.PRIMARY_TARGET
            ],
        )
        ground_truth_chain_recall = EvaluationMetricResult.create(
            metric_name=EvaluationMetricName.GROUND_TRUTH_CHAIN_RECALL,
            numerator_ids=[
                item.ground_truth_chain_id
                for item in recoveries
                if item.evaluation_scope is EvaluationScope.PRIMARY_TARGET
                and item.case_label is BenchmarkCaseLabel.POSITIVE_FEASIBLE
                and item.recovered
            ],
            denominator_ids=[
                item.ground_truth_chain_id
                for item in recoveries
                if item.evaluation_scope is EvaluationScope.PRIMARY_TARGET
                and item.case_label is BenchmarkCaseLabel.POSITIVE_FEASIBLE
            ],
        )
        negative_control_false_positive_rate = EvaluationMetricResult.create(
            metric_name=(
                EvaluationMetricName.NEGATIVE_CONTROL_FALSE_POSITIVE_RATE
            ),
            numerator_ids=[
                item.candidate_id
                for item in assessments
                if item.evaluation_scope is EvaluationScope.PRIMARY_TARGET
                and item.case_label is BenchmarkCaseLabel.NEGATIVE_CONTROL
                and item.negative_control_false_positive
            ],
            denominator_ids=[
                item.candidate_id
                for item in assessments
                if item.evaluation_scope is EvaluationScope.PRIMARY_TARGET
                and item.case_label is BenchmarkCaseLabel.NEGATIVE_CONTROL
            ],
        )
        primary_case_ids = [
            item.id
            for item in detached_manifest.cases
            if item.evaluation_scope is EvaluationScope.PRIMARY_TARGET
        ]
        finalized_primary_case_ids = [
            case.id
            for case in detached_manifest.cases
            if case.evaluation_scope is EvaluationScope.PRIMARY_TARGET
            and run_by_case[case.id].disposition
            is BenchmarkCaseRunDisposition.CANDIDATE
        ]
        primary_case_coverage = EvaluationMetricResult.create(
            metric_name=EvaluationMetricName.PRIMARY_CASE_COVERAGE,
            numerator_ids=finalized_primary_case_ids,
            denominator_ids=primary_case_ids,
        )
        primary_scope_complete = (
            primary_case_coverage.numerator
            == primary_case_coverage.denominator
        )
        primary_assessments = [
            item
            for item in assessments
            if item.evaluation_scope is EvaluationScope.PRIMARY_TARGET
        ]
        claim_counts = {
            status: sum(
                item.claim_binding_status is status
                for item in primary_assessments
            )
            for status in ModelClaimBindingStatus
        }
        feasibility_counts = {
            status: sum(
                item.chain_feasibility_status is status
                for item in primary_assessments
            )
            for status in ChainFeasibilityStatus
        }
        metrics = (
            verification_hit_rate,
            ground_truth_chain_recall,
            negative_control_false_positive_rate,
            primary_case_coverage,
        )
        report_id = benchmark_evaluation_report_id(
            runner_contract=self.contract,
            benchmark_manifest_id=detached_manifest.id,
            benchmark_version=detached_manifest.benchmark_version,
            case_run_record_ids=[item.id for item in runs],
            candidate_assessment_ids=[item.id for item in assessments],
            ground_truth_recovery_ids=[item.id for item in recoveries],
            metric_result_ids=[item.id for item in metrics],
            primary_scope_complete=primary_scope_complete,
            claim_binding_status_counts=claim_counts,
            feasibility_status_counts=feasibility_counts,
        )
        return BenchmarkEvaluationReport(
            id=report_id,
            runner_contract=self.contract,
            benchmark_manifest_id=detached_manifest.id,
            benchmark_version=detached_manifest.benchmark_version,
            case_run_record_ids=[item.id for item in runs],
            candidate_assessments=assessments,
            ground_truth_recoveries=recoveries,
            verification_hit_rate=verification_hit_rate,
            ground_truth_chain_recall=ground_truth_chain_recall,
            negative_control_false_positive_rate=(
                negative_control_false_positive_rate
            ),
            primary_case_coverage=primary_case_coverage,
            primary_scope_complete=primary_scope_complete,
            claim_binding_status_counts=claim_counts,
            feasibility_status_counts=feasibility_counts,
            metadata={
                "aggregation_scope": "frozen_outputs_only",
                "ground_truth_comparison": "post_finalization_only",
                "threshold_interpretation_performed": False,
            },
        )

    @staticmethod
    def _snapshot_manifest(value: object) -> BenchmarkManifest:
        if not isinstance(value, BenchmarkManifest):
            raise InvalidBenchmarkEvaluationInputError(
                "benchmark runner requires BenchmarkManifest"
            )
        try:
            return BenchmarkManifest.model_validate(value.model_dump(mode="json"))
        except (ValidationError, TypeError, ValueError) as exc:
            raise InvalidBenchmarkEvaluationInputError(
                "benchmark manifest failed detached revalidation"
            ) from exc

    @staticmethod
    def _snapshot_run(value: object) -> BenchmarkCaseRunRecord:
        if not isinstance(value, BenchmarkCaseRunRecord):
            raise InvalidBenchmarkEvaluationInputError(
                "benchmark runner requires BenchmarkCaseRunRecord inputs"
            )
        try:
            return BenchmarkCaseRunRecord.model_validate(
                value.model_dump(mode="json")
            )
        except (ValidationError, TypeError, ValueError) as exc:
            raise InvalidBenchmarkEvaluationInputError(
                "benchmark case-run record failed detached revalidation"
            ) from exc

    @staticmethod
    def _validate_case_run(
        case: EvaluationBenchmarkCase,
        run: BenchmarkCaseRunRecord,
    ) -> None:
        if (
            run.benchmark_case_id,
            run.architecture,
        ) != (case.id, case.architecture):
            raise BenchmarkEvaluationBindingError(
                "case-run record and manifest case binding mismatch"
            )
        if (
            run.disposition
            is BenchmarkCaseRunDisposition.PREDECLARED_EXCLUDED
            and case.evaluation_scope is not EvaluationScope.EXCLUDED_UNSUPPORTED
        ):
            raise BenchmarkCaseAccountingError(
                "predeclared exclusion requires excluded_unsupported scope"
            )
        if run.disposition is not BenchmarkCaseRunDisposition.CANDIDATE:
            return
        bundle = run.candidate_bundle
        if bundle is None:  # pragma: no cover - model enforces shape
            raise InvalidBenchmarkEvaluationInputError(
                "candidate case run lost its bundle"
            )
        candidate = bundle.candidate
        feasibility = bundle.feasibility
        if (
            candidate.benchmark_case_id,
            candidate.architecture,
        ) != (case.id, case.architecture):
            raise BenchmarkEvaluationBindingError(
                "candidate assigned to the wrong manifest case"
            )
        if (
            feasibility.artifact_id,
            feasibility.artifact_sha256,
        ) != (
            case.artifact.artifact_id,
            case.artifact.artifact_sha256,
        ):
            raise BenchmarkEvaluationBindingError(
                "feasibility artifact does not match benchmark case artifact"
            )

    @classmethod
    def _assess_candidate(
        cls,
        manifest_id: str,
        case: EvaluationBenchmarkCase,
        bundle: CandidateEvaluationBundle,
    ) -> BenchmarkCandidateAssessment:
        prerequisite = (
            bundle.claim_binding.status is ModelClaimBindingStatus.ALIGNED
            and bundle.feasibility.status
            is ChainFeasibilityStatus.CONFIRMED_FEASIBLE
        )
        matches = []
        if prerequisite and case.label is BenchmarkCaseLabel.POSITIVE_FEASIBLE:
            matches = [
                truth.id
                for truth in case.ground_truth_chains
                if cls._matches_ground_truth(bundle, truth)
            ]
        return BenchmarkCandidateAssessment.create(
            benchmark_manifest_id=manifest_id,
            benchmark_case_id=case.id,
            candidate_id=bundle.candidate.id,
            architecture=case.architecture,
            evaluation_scope=case.evaluation_scope,
            case_label=case.label,
            claim_binding_assessment_id=bundle.claim_binding.id,
            claim_binding_status=bundle.claim_binding.status,
            chain_feasibility_assessment_id=bundle.feasibility.id,
            chain_feasibility_status=bundle.feasibility.status,
            matched_ground_truth_chain_ids=matches,
            metadata={
                "comparison_scope": "frozen_candidate_to_frozen_ground_truth",
                "domain_truth_creation": False,
            },
        )

    @staticmethod
    def _matches_ground_truth(
        bundle: CandidateEvaluationBundle,
        truth: GroundTruthChain,
    ) -> bool:
        candidate = bundle.candidate
        if (
            candidate.cross_layer_interaction_id
            != truth.cross_layer_interaction.id
        ):
            return False
        if (
            truth.expected_attack_pattern_reference is not None
            and candidate.attack_pattern_reference
            != truth.expected_attack_pattern_reference
        ):
            return False
        if truth.hardware_trigger_signature_id is not None:
            triggerability = bundle.triggerability
            if (
                triggerability is None
                or triggerability.signature_id
                != truth.hardware_trigger_signature_id
            ):
                return False
        return True

    @staticmethod
    def _ground_truth_recoveries(
        manifest: BenchmarkManifest,
        assessments: list[BenchmarkCandidateAssessment],
    ) -> list[GroundTruthRecoveryRecord]:
        recoveries: list[GroundTruthRecoveryRecord] = []
        for case in manifest.cases:
            case_assessments = [
                item
                for item in assessments
                if item.benchmark_case_id == case.id
            ]
            for truth in case.ground_truth_chains:
                recovered_ids = [
                    item.candidate_id
                    for item in case_assessments
                    if truth.id in item.matched_ground_truth_chain_ids
                ]
                recoveries.append(
                    GroundTruthRecoveryRecord.create(
                        benchmark_manifest_id=manifest.id,
                        benchmark_case_id=case.id,
                        ground_truth_chain_id=truth.id,
                        evaluation_scope=case.evaluation_scope,
                        case_label=case.label,
                        recovered_candidate_ids=recovered_ids,
                        metadata={
                            "matching_semantics": "exact_post_finalization_only"
                        },
                    )
                )
        return recoveries
