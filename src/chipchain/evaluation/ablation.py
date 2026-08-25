"""Phase 10C experiment-only prompt audit and ablation aggregation services."""

from __future__ import annotations

from pydantic import ValidationError

from chipchain.evaluation.ablation_models import (
    AblationComparisonReport,
    AblationConditionResult,
    AblationExperimentPlan,
    AblationMetricDelta,
    ContextObjectiveUpperBoundRate,
    ContextObjectiveUpperBoundResult,
    PromptVisibilityAudit,
    prompt_visibility_audit_id,
    structured_prompt_sha256,
)
from chipchain.evaluation.benchmark_models import (
    PHASE10B_RUNNER_CONTRACT,
    BenchmarkCaseRunRecord,
    EvaluationMetricResult,
)
from chipchain.evaluation.enums import (
    AblationConditionKind,
    BenchmarkCaseLabel,
    BenchmarkCaseRunDisposition,
    ChainFeasibilityStatus,
    EvaluationMetricName,
    EvaluationScope,
    PromptVisibilityAuditStatus,
)
from chipchain.evaluation.models import BenchmarkManifest, GroundTruthChain, _canonical_hash
from chipchain.reasoning.models import StructuredPromptRequest


class PromptVisibilityAuditor:
    """Audit exact hidden references after prompt construction without mutation."""

    @staticmethod
    def audit(
        prompt: StructuredPromptRequest,
        *,
        hidden_reference_ids: list[str],
        metadata: dict[str, object] | None = None,
    ) -> PromptVisibilityAudit:
        if not isinstance(prompt, StructuredPromptRequest):
            raise TypeError("prompt audit requires StructuredPromptRequest")
        snapshot = StructuredPromptRequest.model_validate(
            prompt.model_dump(mode="json")
        )
        hidden = sorted(item.strip() for item in hidden_reference_ids)
        if not all(hidden) or len(hidden) != len(set(hidden)):
            raise ValueError("hidden prompt references must be non-empty and unique")
        prompt_text = snapshot.system_prompt + "\n" + snapshot.user_prompt
        leaked = [item for item in hidden if item in prompt_text]
        status = (
            PromptVisibilityAuditStatus.LEAK_DETECTED
            if leaked
            else PromptVisibilityAuditStatus.PASS
        )
        prompt_sha256 = structured_prompt_sha256(
            {
                "architecture": snapshot.architecture.value,
                "candidate_id": snapshot.candidate_id,
                "schema_name": snapshot.schema_name,
                "system_prompt": snapshot.system_prompt,
                "user_prompt": snapshot.user_prompt,
            }
        )
        identity = prompt_visibility_audit_id(
            prompt_sha256=prompt_sha256,
            hidden_reference_ids=hidden,
            leaked_reference_ids=leaked,
            status=status,
        )
        return PromptVisibilityAudit(
            id=identity,
            prompt_sha256=prompt_sha256,
            hidden_reference_ids=hidden,
            leaked_reference_ids=leaked,
            status=status,
            metadata=metadata or {},
        )


class ContextObjectiveUpperBoundEvaluator:
    """Remove only the model-claim gate from exact Phase 10B comparison."""

    def evaluate(
        self,
        manifest: BenchmarkManifest,
        case_run_records: list[BenchmarkCaseRunRecord],
    ) -> ContextObjectiveUpperBoundResult:
        detached_manifest = self._snapshot_manifest(manifest)
        runs = [self._snapshot_run(item) for item in case_run_records]
        run_by_case: dict[str, BenchmarkCaseRunRecord] = {}
        for run in runs:
            if run.benchmark_case_id in run_by_case:
                raise ValueError("duplicate upper-bound case-run record")
            run_by_case[run.benchmark_case_id] = run
        manifest_ids = {item.id for item in detached_manifest.cases}
        if set(run_by_case) != manifest_ids:
            raise ValueError("upper-bound case accounting must exactly match manifest")

        denominator_ids: list[str] = []
        numerator_ids: list[str] = []
        matched_truth_ids: list[str] = []
        finalized_primary_case_ids: list[str] = []
        primary_case_ids = [
            case.id
            for case in detached_manifest.cases
            if case.evaluation_scope is EvaluationScope.PRIMARY_TARGET
        ]
        for case in detached_manifest.cases:
            run = run_by_case[case.id]
            self._validate_case_run(case, run)
            if run.disposition is not BenchmarkCaseRunDisposition.CANDIDATE:
                continue
            bundle = run.candidate_bundle
            if bundle is None:  # pragma: no cover - contract enforces shape
                raise ValueError("candidate case-run lost its bundle")
            if case.evaluation_scope is not EvaluationScope.PRIMARY_TARGET:
                continue
            finalized_primary_case_ids.append(case.id)
            denominator_ids.append(bundle.candidate.id)
            if (
                case.label is not BenchmarkCaseLabel.POSITIVE_FEASIBLE
                or bundle.feasibility.status
                is not ChainFeasibilityStatus.CONFIRMED_FEASIBLE
            ):
                continue
            matches = [
                truth.id
                for truth in case.ground_truth_chains
                if self._matches_ground_truth(bundle, truth)
            ]
            if matches:
                numerator_ids.append(bundle.candidate.id)
                matched_truth_ids.extend(matches)

        rate = ContextObjectiveUpperBoundRate.create(
            numerator_ids=numerator_ids,
            denominator_ids=denominator_ids,
        )
        coverage = EvaluationMetricResult.create(
            metric_name=EvaluationMetricName.PRIMARY_CASE_COVERAGE,
            numerator_ids=finalized_primary_case_ids,
            denominator_ids=primary_case_ids,
        )
        return ContextObjectiveUpperBoundResult.create(
            benchmark_manifest_id=detached_manifest.id,
            benchmark_version=detached_manifest.benchmark_version,
            rate=rate,
            primary_case_coverage=coverage,
            matched_ground_truth_chain_ids=matched_truth_ids,
            metadata={
                "diagnostic_scope": "context_and_objective_verifier_only",
                "model_claim_gate_ignored": True,
                "verification_hit_rate": False,
            },
        )

    @staticmethod
    def _snapshot_manifest(value: object) -> BenchmarkManifest:
        if not isinstance(value, BenchmarkManifest):
            raise TypeError("upper bound requires BenchmarkManifest")
        try:
            return BenchmarkManifest.model_validate(value.model_dump(mode="json"))
        except (ValidationError, TypeError, ValueError) as exc:
            raise ValueError("manifest failed detached revalidation") from exc

    @staticmethod
    def _snapshot_run(value: object) -> BenchmarkCaseRunRecord:
        if not isinstance(value, BenchmarkCaseRunRecord):
            raise TypeError("upper bound requires BenchmarkCaseRunRecord inputs")
        try:
            return BenchmarkCaseRunRecord.model_validate(value.model_dump(mode="json"))
        except (ValidationError, TypeError, ValueError) as exc:
            raise ValueError("case-run failed detached revalidation") from exc

    @staticmethod
    def _validate_case_run(case: object, run: BenchmarkCaseRunRecord) -> None:
        if (run.benchmark_case_id, run.architecture) != (
            case.id,
            case.architecture,
        ):
            raise ValueError("upper-bound case-run binding mismatch")
        if (
            run.disposition is BenchmarkCaseRunDisposition.PREDECLARED_EXCLUDED
            and case.evaluation_scope is not EvaluationScope.EXCLUDED_UNSUPPORTED
        ):
            raise ValueError("upper-bound predeclared exclusion scope mismatch")
        if run.disposition is BenchmarkCaseRunDisposition.CANDIDATE:
            bundle = run.candidate_bundle
            if bundle is None:  # pragma: no cover
                raise ValueError("candidate run requires bundle")
            if (bundle.candidate.benchmark_case_id, bundle.candidate.architecture) != (
                case.id,
                case.architecture,
            ):
                raise ValueError("upper-bound candidate case mismatch")
            if (
                bundle.feasibility.artifact_id,
                bundle.feasibility.artifact_sha256,
            ) != (case.artifact.artifact_id, case.artifact.artifact_sha256):
                raise ValueError("upper-bound feasibility artifact mismatch")

    @staticmethod
    def _matches_ground_truth(bundle: object, truth: GroundTruthChain) -> bool:
        candidate = bundle.candidate
        if candidate.cross_layer_interaction_id != truth.cross_layer_interaction.id:
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


class AblationComparisonBuilder:
    """Compare all predeclared conditions without changing Phase 10B metrics."""

    @staticmethod
    def compare(
        plan: AblationExperimentPlan,
        condition_results: list[AblationConditionResult],
        *,
        metadata: dict[str, object] | None = None,
    ) -> AblationComparisonReport:
        detached_plan = AblationExperimentPlan.model_validate(
            plan.model_dump(mode="json")
        )
        results = [
            AblationConditionResult.model_validate(item.model_dump(mode="json"))
            for item in condition_results
        ]
        if len(results) != len(AblationConditionKind) or {
            item.condition_kind for item in results
        } != set(AblationConditionKind):
            raise ValueError("all predeclared ablation conditions must be accounted")
        if any(
            item.ablation_plan_id != detached_plan.id
            or item.benchmark_manifest_id != detached_plan.benchmark_manifest_id
            for item in results
        ):
            raise ValueError("ablation result plan or manifest mismatch")

        by_kind = {item.condition_kind: item for item in results}
        reports = {
            kind: item.benchmark_evaluation_report
            for kind, item in by_kind.items()
            if item.benchmark_evaluation_report is not None
        }
        for report in reports.values():
            if (
                report.benchmark_manifest_id != detached_plan.benchmark_manifest_id
                or report.benchmark_version != detached_plan.benchmark_version
                or report.runner_contract != PHASE10B_RUNNER_CONTRACT
            ):
                raise ValueError("model conditions must use the same frozen benchmark")
        upper_result = by_kind[
            AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND
        ].context_objective_upper_bound_result
        if upper_result is not None and (
            upper_result.benchmark_manifest_id != detached_plan.benchmark_manifest_id
            or upper_result.benchmark_version != detached_plan.benchmark_version
        ):
            raise ValueError("upper-bound condition uses another benchmark")

        full = reports.get(AblationConditionKind.FULL_CONTEXT_MODEL)
        masked = reports.get(AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL)
        no_model = reports.get(AblationConditionKind.NO_MODEL_BASELINE)
        full_rate = full.verification_hit_rate if full else None
        masked_rate = masked.verification_hit_rate if masked else None
        no_model_rate = no_model.verification_hit_rate if no_model else None
        upper_rate = upper_result.rate if upper_result else None
        coverage = {kind: report.primary_case_coverage for kind, report in reports.items()}
        recall = {kind: report.ground_truth_chain_recall for kind, report in reports.items()}
        negative = {
            kind: report.negative_control_false_positive_rate
            for kind, report in reports.items()
        }
        coverage_comparable = AblationComparisonBuilder._coverage_comparable(
            reports, upper_result
        )
        deltas = (
            AblationMetricDelta.create(full_rate, masked_rate),
            AblationMetricDelta.create(full_rate, no_model_rate),
            AblationMetricDelta.create(upper_rate, full_rate),
        )
        payload = {
            "ablation_plan_id": detached_plan.id,
            "benchmark_manifest_id": detached_plan.benchmark_manifest_id,
            "condition_result_ids": sorted(item.id for item in results),
            "coverage_comparable": coverage_comparable,
            "delta_ids": sorted(item.id for item in deltas),
            "metric_ids": sorted(
                item.id
                for item in (full_rate, masked_rate, no_model_rate, upper_rate)
                if item is not None
            ),
            "coverage_metric_ids": sorted(item.id for item in coverage.values()),
            "ground_truth_recall_metric_ids": sorted(item.id for item in recall.values()),
            "negative_false_positive_metric_ids": sorted(
                item.id for item in negative.values()
            ),
        }
        return AblationComparisonReport(
            id=_canonical_hash("ablation-comparison-report", payload),
            ablation_plan_id=detached_plan.id,
            benchmark_manifest_id=detached_plan.benchmark_manifest_id,
            condition_results=results,
            full_context_verification_hit_rate=full_rate,
            masked_context_verification_hit_rate=masked_rate,
            no_model_verification_hit_rate=no_model_rate,
            context_objective_upper_bound_rate=upper_rate,
            coverage_by_condition=coverage,
            ground_truth_recall_by_condition=recall,
            negative_false_positive_rate_by_condition=negative,
            full_minus_masked_delta=deltas[0],
            full_minus_no_model_delta=deltas[1],
            upper_bound_minus_full_delta=deltas[2],
            coverage_comparable=coverage_comparable,
            metadata=metadata or {},
        )

    @staticmethod
    def _coverage_comparable(
        reports: dict[AblationConditionKind, object],
        upper_result: ContextObjectiveUpperBoundResult | None,
    ) -> bool:
        model_kinds = {
            AblationConditionKind.FULL_CONTEXT_MODEL,
            AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
            AblationConditionKind.NO_MODEL_BASELINE,
        }
        if set(reports) != model_kinds or upper_result is None:
            return False
        metrics = [report.primary_case_coverage for report in reports.values()]
        metrics.append(upper_result.primary_case_coverage)
        first_cohort = metrics[0].denominator_ids
        return all(
            metric.numerator == metric.denominator
            and metric.denominator_ids == first_cohort
            for metric in metrics
        )
