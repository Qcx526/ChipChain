"""Offline Phase 10B deterministic benchmark evaluation tests."""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.evaluation import (
    BenchmarkCaseAccountingError,
    BenchmarkCaseExecutionFailure,
    BenchmarkCaseLabel,
    BenchmarkCaseRunRecord,
    BenchmarkEvaluationBindingError,
    BenchmarkEvaluationReport,
    BenchmarkEvaluationRunner,
    BenchmarkExecutionFailureCode,
    BenchmarkExecutionStage,
    BenchmarkManifest,
    ChainFeasibilityAssessment,
    ChainFeasibilityReason,
    ChainFeasibilityStatus,
    CandidateEvaluationBundle,
    EvaluationBenchmarkCase,
    EvaluationMetricName,
    EvaluationMetricResult,
    EvaluationScope,
    FinalizedCandidateRecord,
    GroundTruthRecoveryRecord,
    InvalidBenchmarkEvaluationInputError,
    ModelClaimBindingAssessment,
    ModelClaimBindingReason,
    ModelClaimBindingStatus,
    finalized_candidate_id,
)
from chipchain.hardware_trigger import (
    ArmExecutionMode,
    TriggerabilityAggregationResult,
    TriggerabilityStatus,
)
from chipchain.models import (
    Architecture,
    AttackChain,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    Layer,
)
from chipchain.reasoning import (
    ModelAuthoredChainClaim,
    ReasoningAgentType,
)
from chipchain.verification.models import VerificationRecord


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/evaluation/phase10a_owned_arm.json"


def _fixture_manifest() -> BenchmarkManifest:
    return BenchmarkManifest.model_validate_json(FIXTURE.read_text("utf-8"))


def _case(
    manifest: BenchmarkManifest,
    label: BenchmarkCaseLabel,
) -> EvaluationBenchmarkCase:
    return next(item for item in manifest.cases if item.label is label)


def _manifest(cases: list[EvaluationBenchmarkCase]) -> BenchmarkManifest:
    return BenchmarkManifest.create(
        benchmark_version=cases[0].benchmark_version,
        architecture_scope=[Architecture.ARM],
        cases=cases,
        metadata={"fixture": True},
    )


def _case_with_scope(
    case: EvaluationBenchmarkCase,
    scope: EvaluationScope,
) -> EvaluationBenchmarkCase:
    return EvaluationBenchmarkCase.create(
        benchmark_version=case.benchmark_version,
        architecture=case.architecture,
        source_kind=case.source_kind,
        label=case.label,
        artifact=case.artifact,
        ground_truth_chains=case.ground_truth_chains,
        source_reference_ids=case.source_reference_ids,
        evaluation_scope=scope,
        metadata=case.metadata,
    )


def _different_type_two_interaction(suffix: str) -> CrossLayerInteraction:
    return CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=(
            CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
        ),
        source_layer=Layer.FIRMWARE,
        target_layer=Layer.HARDWARE,
        target_vulnerability_ids=[f"synthetic-other-hardware-{suffix}"],
        trigger_behavior_ids=[f"synthetic-other-trigger-{suffix}"],
        hardware_resource_ids=[f"synthetic-other-resource-{suffix}"],
        referenced_architectures=[Architecture.ARM],
    )


def _type_three_interaction() -> CrossLayerInteraction:
    return CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=(
            CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
        ),
        source_layer=Layer.HARDWARE,
        target_layer=Layer.FIRMWARE,
        initiating_vulnerability_ids=["synthetic-type-three-hardware"],
        affected_execution_ids=["synthetic-type-three-execution"],
        referenced_architectures=[Architecture.ARM],
    )


def _claim(
    interaction: CrossLayerInteraction,
    *,
    incomplete: bool = False,
    mismatched: bool = False,
) -> ModelAuthoredChainClaim:
    return ModelAuthoredChainClaim.create(
        architecture=Architecture.ARM,
        author_role=ReasoningAgentType.ATTACK_CHAIN,
        interaction_type=interaction.interaction_type,
        initiating_vulnerability_ids=(
            interaction.initiating_vulnerability_ids
        ),
        target_vulnerability_ids=(
            ["synthetic-model-selected-wrong-target"]
            if mismatched
            else interaction.target_vulnerability_ids
        ),
        trigger_behavior_ids=(
            [] if incomplete else interaction.trigger_behavior_ids
        ),
        propagation_behavior_ids=interaction.propagation_behavior_ids,
        affected_execution_ids=interaction.affected_execution_ids,
        fault_state_ids=interaction.fault_state_ids,
        hardware_resource_ids=interaction.hardware_resource_ids,
        security_mechanism_ids=interaction.security_mechanism_ids,
    )


def _candidate(
    case: EvaluationBenchmarkCase,
    interaction: CrossLayerInteraction | None,
    claim: ModelAuthoredChainClaim | None,
    *,
    attack_pattern_reference: str | None = "synthetic-attack-pattern",
    confidence: float = 0.0,
    proposition_suffix: str = "base",
) -> FinalizedCandidateRecord:
    values = {
        "benchmark_case_id": case.id,
        "architecture": Architecture.ARM,
        "reasoning_session_id": "reasoning-session:phase10b-fixture",
        "reasoning_context_id": "reasoning-context:phase10b-fixture",
        "workflow_contract": "phase10b-frozen-input-fixture",
        "merged_hypothesis_id": f"attack-hypothesis:{proposition_suffix}",
        "subject_id": "synthetic-phase10b-subject",
        "cross_layer_interaction_id": (
            interaction.id if interaction is not None else None
        ),
        "interaction_type": (
            interaction.interaction_type if interaction is not None else None
        ),
        "direction": interaction.direction if interaction is not None else None,
        "attack_pattern_reference": attack_pattern_reference,
        "affected_components": [
            "synthetic-owned-arm-firmware",
            "synthetic-owned-arm-hardware",
        ],
    }
    identity = finalized_candidate_id(
        **values,
        model_authored_chain_claim_id=claim.id if claim is not None else None,
    )
    return FinalizedCandidateRecord(
        id=identity,
        model_authored_chain_claim=claim,
        model_confidence=confidence,
        metadata={"fixture": True, "synthetic": True, "owned": True},
        **values,
    )


def _binding(
    candidate: FinalizedCandidateRecord,
    status: ModelClaimBindingStatus,
) -> ModelClaimBindingAssessment:
    claim = candidate.model_authored_chain_claim
    if status is ModelClaimBindingStatus.ALIGNED:
        reasons = [ModelClaimBindingReason.CLAIM_ALIGNED]
    elif status is ModelClaimBindingStatus.MISSING:
        reasons = [ModelClaimBindingReason.MODEL_AUTHORED_CLAIM_MISSING]
    elif status is ModelClaimBindingStatus.INCOMPLETE:
        reasons = [ModelClaimBindingReason.CLAIM_REQUIRED_FIELDS_MISSING]
    elif status is ModelClaimBindingStatus.UNBOUND:
        reasons = [
            ModelClaimBindingReason.CANDIDATE_TYPED_INTERACTION_MISSING
        ]
    else:
        reasons = [
            ModelClaimBindingReason.CLAIM_TARGET_VULNERABILITY_MISMATCH
        ]
    return ModelClaimBindingAssessment.from_derived_binding(
        candidate_id=candidate.id,
        benchmark_case_id=candidate.benchmark_case_id,
        architecture=candidate.architecture,
        model_authored_chain_claim_id=claim.id if claim is not None else None,
        candidate_interaction_id=candidate.cross_layer_interaction_id,
        claimed_interaction_type=(
            claim.interaction_type if claim is not None else None
        ),
        candidate_interaction_type=candidate.interaction_type,
        status=status,
        reason_codes=reasons,
        metadata={"fixture": True},
    )


def _triggerability(
    case: EvaluationBenchmarkCase,
    interaction: CrossLayerInteraction,
    status: TriggerabilityStatus,
    *,
    signature_id: str,
) -> TriggerabilityAggregationResult:
    if status is TriggerabilityStatus.NO_STATIC_TRIGGER_MATCH:
        static_ids: list[str] = []
        runtime_ids: list[str] = []
        declared = False
    elif status is TriggerabilityStatus.NOT_OBSERVED_IN_RUNTIME:
        static_ids = ["static-firmware-trigger-match:phase10b"]
        runtime_ids = []
        declared = False
    else:
        static_ids = ["static-firmware-trigger-match:phase10b"]
        runtime_ids = ["runtime-firmware-trigger-occurrence:phase10b"]
        declared = (
            status
            is TriggerabilityStatus.INSUFFICIENT_PRECONDITION_EVIDENCE
        )
    hardware_vulnerability_id = (
        interaction.target_vulnerability_ids[0]
        if interaction.target_vulnerability_ids
        else interaction.initiating_vulnerability_ids[0]
    )
    return TriggerabilityAggregationResult.create(
        signature_id=signature_id,
        hardware_vulnerability_id=hardware_vulnerability_id,
        architecture=Architecture.ARM,
        execution_mode=ArmExecutionMode.A32,
        artifact_id=case.artifact.artifact_id,
        artifact_sha256=case.artifact.artifact_sha256,
        trace_id="runtime-trigger-execution-trace:phase10b",
        raw_trace_sha256="1" * 64,
        static_result_sha256="2" * 64,
        runtime_result_sha256="3" * 64,
        static_match_ids=static_ids,
        runtime_occurrence_ids=runtime_ids,
        declared_preconditions_present=declared,
        metadata={"fixture": True},
    )


def _bundle(
    case: EvaluationBenchmarkCase,
    *,
    binding_status: ModelClaimBindingStatus = ModelClaimBindingStatus.ALIGNED,
    feasibility_status: ChainFeasibilityStatus = (
        ChainFeasibilityStatus.CONFIRMED_FEASIBLE
    ),
    interaction: CrossLayerInteraction | None = None,
    attack_pattern_reference: str | None = "synthetic-attack-pattern",
    signature_id: str | None = None,
    confidence: float = 0.0,
    artifact_case: EvaluationBenchmarkCase | None = None,
    metadata: dict[str, object] | None = None,
) -> CandidateEvaluationBundle:
    if interaction is None and binding_status is not ModelClaimBindingStatus.UNBOUND:
        interaction = (
            _type_three_interaction()
            if feasibility_status is ChainFeasibilityStatus.UNSUPPORTED
            else (
                case.ground_truth_chains[0].cross_layer_interaction
                if case.ground_truth_chains
                else _different_type_two_interaction("negative")
            )
        )
    claim_source = interaction or (
        case.ground_truth_chains[0].cross_layer_interaction
    )
    claim = None
    if binding_status is not ModelClaimBindingStatus.MISSING:
        claim = _claim(
            claim_source,
            incomplete=(
                binding_status is ModelClaimBindingStatus.INCOMPLETE
            ),
            mismatched=(
                binding_status is ModelClaimBindingStatus.MISMATCHED
            ),
        )
    candidate = _candidate(
        case,
        interaction,
        claim,
        attack_pattern_reference=attack_pattern_reference,
        confidence=confidence,
    )
    binding = _binding(candidate, binding_status)
    evaluated_artifact_case = artifact_case or case
    triggerability = None
    infrastructure_failure_id = None
    if feasibility_status is ChainFeasibilityStatus.CONFIRMED_FEASIBLE:
        triggerability_status = TriggerabilityStatus.TRIGGERABLE
    elif feasibility_status is ChainFeasibilityStatus.NOT_SUPPORTED:
        triggerability_status = TriggerabilityStatus.NO_STATIC_TRIGGER_MATCH
    else:
        triggerability_status = None
    if triggerability_status is not None:
        assert interaction is not None
        triggerability = _triggerability(
            evaluated_artifact_case,
            interaction,
            triggerability_status,
            signature_id=(
                signature_id
                or (
                    case.ground_truth_chains[0].hardware_trigger_signature_id
                    if case.ground_truth_chains
                    else "hardware-trigger-signature:phase10b-negative"
                )
            ),
        )
    if feasibility_status is ChainFeasibilityStatus.INFRA_FAILURE:
        infrastructure_failure_id = "objective-evaluation-failure:phase10b"
    feasibility = ChainFeasibilityAssessment.create(
        candidate_id=candidate.id,
        benchmark_case_id=candidate.benchmark_case_id,
        architecture=candidate.architecture,
        interaction_id=candidate.cross_layer_interaction_id,
        interaction_type=candidate.interaction_type,
        artifact_id=evaluated_artifact_case.artifact.artifact_id,
        artifact_sha256=evaluated_artifact_case.artifact.artifact_sha256,
        triggerability_aggregation_id=(
            triggerability.id if triggerability is not None else None
        ),
        triggerability_status=(
            triggerability.status if triggerability is not None else None
        ),
        infrastructure_failure_id=infrastructure_failure_id,
        metadata={"fixture": True},
    )
    assert feasibility.status is feasibility_status
    return CandidateEvaluationBundle.create(
        candidate=candidate,
        claim_binding=binding,
        feasibility=feasibility,
        triggerability=triggerability,
        metadata=metadata or {"fixture": True},
    )


def _owned_runs(
    manifest: BenchmarkManifest,
) -> list[BenchmarkCaseRunRecord]:
    positive = _case(manifest, BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    negative = _case(manifest, BenchmarkCaseLabel.NEGATIVE_CONTROL)
    return [
        BenchmarkCaseRunRecord.from_candidate(_bundle(positive)),
        BenchmarkCaseRunRecord.from_candidate(
            _bundle(
                negative,
                binding_status=ModelClaimBindingStatus.MISSING,
                feasibility_status=ChainFeasibilityStatus.UNRESOLVED,
            )
        ),
    ]


def test_owned_synthetic_fixture_has_exact_contract_acceptance_ratios() -> None:
    manifest = _fixture_manifest()
    report = BenchmarkEvaluationRunner().evaluate(
        manifest,
        _owned_runs(manifest),
    )
    positive = next(
        item
        for item in report.candidate_assessments
        if item.case_label is BenchmarkCaseLabel.POSITIVE_FEASIBLE
    )

    assert positive.strict_hit is True
    assert len(positive.matched_ground_truth_chain_ids) == 1
    assert report.ground_truth_recoveries[0].recovered is True
    assert (
        report.verification_hit_rate.numerator,
        report.verification_hit_rate.denominator,
    ) == (1, 2)
    assert (
        report.ground_truth_chain_recall.numerator,
        report.ground_truth_chain_recall.denominator,
    ) == (1, 1)
    assert (
        report.negative_control_false_positive_rate.numerator,
        report.negative_control_false_positive_rate.denominator,
    ) == (0, 1)
    assert (
        report.primary_case_coverage.numerator,
        report.primary_case_coverage.denominator,
    ) == (2, 2)
    assert report.primary_scope_complete is True
    assert report.verification_hit_rate.ratio == 0.5
    assert report.verification_hit_rate.percentage == 50.0


@pytest.mark.parametrize(
    "binding_status",
    [
        ModelClaimBindingStatus.MISSING,
        ModelClaimBindingStatus.INCOMPLETE,
        ModelClaimBindingStatus.MISMATCHED,
    ],
)
def test_non_aligned_claim_statuses_block_strict_hit(
    binding_status: ModelClaimBindingStatus,
) -> None:
    case = _case(_fixture_manifest(), BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    bundle = _bundle(case, binding_status=binding_status)
    report = BenchmarkEvaluationRunner().evaluate(
        _manifest([case]),
        [BenchmarkCaseRunRecord.from_candidate(bundle)],
    )

    assert report.candidate_assessments[0].strict_hit is False
    assert report.ground_truth_recoveries[0].recovered is False
    assert bundle.feasibility.status is ChainFeasibilityStatus.CONFIRMED_FEASIBLE


def test_unbound_claim_blocks_hit_without_fabricating_typed_context() -> None:
    case = _case(_fixture_manifest(), BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    bundle = _bundle(
        case,
        binding_status=ModelClaimBindingStatus.UNBOUND,
        feasibility_status=ChainFeasibilityStatus.UNRESOLVED,
    )
    report = BenchmarkEvaluationRunner().evaluate(
        _manifest([case]),
        [BenchmarkCaseRunRecord.from_candidate(bundle)],
    )

    assert report.candidate_assessments[0].strict_hit is False
    assert bundle.candidate.cross_layer_interaction_id is None


@pytest.mark.parametrize(
    "status",
    [
        ChainFeasibilityStatus.NOT_SUPPORTED,
        ChainFeasibilityStatus.UNRESOLVED,
        ChainFeasibilityStatus.UNSUPPORTED,
        ChainFeasibilityStatus.INFRA_FAILURE,
    ],
)
def test_non_confirmed_feasibility_statuses_remain_measurable_non_hits(
    status: ChainFeasibilityStatus,
) -> None:
    case = _case(_fixture_manifest(), BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    bundle = _bundle(case, feasibility_status=status)
    report = BenchmarkEvaluationRunner().evaluate(
        _manifest([case]),
        [BenchmarkCaseRunRecord.from_candidate(bundle)],
    )

    assessment = report.candidate_assessments[0]
    assert assessment.strict_hit is False
    assert assessment.chain_feasibility_status is status
    assert report.feasibility_status_counts[status] == 1
    assert report.verification_hit_rate.denominator == 1


@pytest.mark.parametrize("mismatch", ["interaction", "pattern", "signature"])
def test_objectively_feasible_off_ground_truth_candidate_is_not_a_hit(
    mismatch: str,
) -> None:
    case = _case(_fixture_manifest(), BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    kwargs: dict[str, object] = {}
    if mismatch == "interaction":
        kwargs["interaction"] = _different_type_two_interaction("off-truth")
    elif mismatch == "pattern":
        kwargs["attack_pattern_reference"] = "synthetic-other-pattern"
    else:
        kwargs["signature_id"] = "hardware-trigger-signature:other"
    bundle = _bundle(case, **kwargs)
    report = BenchmarkEvaluationRunner().evaluate(
        _manifest([case]),
        [BenchmarkCaseRunRecord.from_candidate(bundle)],
    )

    assessment = report.candidate_assessments[0]
    assert bundle.feasibility.status is ChainFeasibilityStatus.CONFIRMED_FEASIBLE
    assert assessment.matched_ground_truth_chain_ids == []
    assert assessment.strict_hit is False
    assert report.ground_truth_recoveries[0].recovered is False


def test_negative_aligned_confirmed_candidate_is_false_positive_never_hit() -> None:
    case = _case(_fixture_manifest(), BenchmarkCaseLabel.NEGATIVE_CONTROL)
    bundle = _bundle(case)
    report = BenchmarkEvaluationRunner().evaluate(
        _manifest([case]),
        [BenchmarkCaseRunRecord.from_candidate(bundle)],
    )
    assessment = report.candidate_assessments[0]

    assert assessment.strict_hit is False
    assert assessment.matched_ground_truth_chain_ids == []
    assert assessment.negative_control_false_positive is True
    assert report.negative_control_false_positive_rate.numerator_ids == [
        bundle.candidate.id
    ]
    assert report.negative_control_false_positive_rate.ratio == 1.0


def test_pre_finalization_failure_lowers_coverage_not_candidate_denominator() -> None:
    manifest = _fixture_manifest()
    positive = _case(manifest, BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    negative = _case(manifest, BenchmarkCaseLabel.NEGATIVE_CONTROL)
    failure = BenchmarkCaseExecutionFailure.create(
        benchmark_case_id=negative.id,
        architecture=Architecture.ARM,
        stage=BenchmarkExecutionStage.REASONING_SESSION,
        failure_code=BenchmarkExecutionFailureCode.PROVIDER_EXECUTION_FAILED,
        metadata={"bounded_reason": "offline fixture failure"},
    )
    report = BenchmarkEvaluationRunner().evaluate(
        manifest,
        [
            BenchmarkCaseRunRecord.from_candidate(_bundle(positive)),
            BenchmarkCaseRunRecord.from_execution_failure(failure),
        ],
    )

    assert report.primary_case_coverage.numerator == 1
    assert report.primary_case_coverage.denominator == 2
    assert report.primary_scope_complete is False
    assert report.verification_hit_rate.denominator == 1
    assert len(report.case_run_record_ids) == 2


def test_missing_duplicate_and_extra_case_runs_fail_closed() -> None:
    manifest = _fixture_manifest()
    runs = _owned_runs(manifest)
    runner = BenchmarkEvaluationRunner()

    with pytest.raises(BenchmarkCaseAccountingError, match="missing"):
        runner.evaluate(manifest, runs[:1])
    with pytest.raises(BenchmarkCaseAccountingError, match="duplicate"):
        runner.evaluate(manifest, [runs[0], runs[0], runs[1]])
    extra = BenchmarkCaseRunRecord.predeclared_excluded(
        benchmark_case_id="evaluation-benchmark-case:extra",
        architecture=Architecture.ARM,
    )
    with pytest.raises(BenchmarkCaseAccountingError, match="not present"):
        runner.evaluate(manifest, [*runs, extra])


def test_case_artifact_mismatch_is_invalid_not_a_metric_miss() -> None:
    manifest = _fixture_manifest()
    positive = _case(manifest, BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    negative = _case(manifest, BenchmarkCaseLabel.NEGATIVE_CONTROL)
    wrong_artifact_bundle = _bundle(positive, artifact_case=negative)

    with pytest.raises(BenchmarkEvaluationBindingError, match="artifact"):
        BenchmarkEvaluationRunner().evaluate(
            _manifest([positive]),
            [BenchmarkCaseRunRecord.from_candidate(wrong_artifact_bundle)],
        )


def test_candidate_assessment_and_triggerability_mismatches_fail_closed() -> None:
    case = _case(_fixture_manifest(), BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    first = _bundle(case)
    other_candidate = _candidate(
        case,
        first.candidate.model_authored_chain_claim
        and case.ground_truth_chains[0].cross_layer_interaction,
        first.candidate.model_authored_chain_claim,
        proposition_suffix="other",
    )
    with pytest.raises(BenchmarkEvaluationBindingError, match="exactly bound"):
        CandidateEvaluationBundle.create(
            candidate=other_candidate,
            claim_binding=first.claim_binding,
            feasibility=first.feasibility,
            triggerability=first.triggerability,
        )

    assert first.triggerability is not None
    other_trigger = _triggerability(
        case,
        case.ground_truth_chains[0].cross_layer_interaction,
        TriggerabilityStatus.TRIGGERABLE,
        signature_id="hardware-trigger-signature:mismatched-result",
    )
    with pytest.raises(BenchmarkEvaluationBindingError, match="exactly bound"):
        CandidateEvaluationBundle.create(
            candidate=first.candidate,
            claim_binding=first.claim_binding,
            feasibility=first.feasibility,
            triggerability=other_trigger,
        )


def test_secondary_candidate_is_auditable_but_absent_from_primary_metrics() -> None:
    base = _case(_fixture_manifest(), BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    case = _case_with_scope(base, EvaluationScope.SECONDARY_ONLY)
    report = BenchmarkEvaluationRunner().evaluate(
        _manifest([case]),
        [BenchmarkCaseRunRecord.from_candidate(_bundle(case))],
    )

    assert len(report.candidate_assessments) == 1
    assert report.candidate_assessments[0].strict_hit is False
    assert report.verification_hit_rate.denominator == 0
    assert report.verification_hit_rate.defined is False
    assert report.ground_truth_chain_recall.denominator == 0


def test_excluded_case_requires_predeclared_scope_and_stays_out_of_metrics() -> None:
    base = _case(_fixture_manifest(), BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    excluded = _case_with_scope(base, EvaluationScope.EXCLUDED_UNSUPPORTED)
    run = BenchmarkCaseRunRecord.predeclared_excluded(
        benchmark_case_id=excluded.id,
        architecture=Architecture.ARM,
    )
    report = BenchmarkEvaluationRunner().evaluate(_manifest([excluded]), [run])

    assert report.candidate_assessments == []
    assert report.verification_hit_rate.defined is False
    assert report.primary_case_coverage.defined is False
    assert report.primary_scope_complete is True

    primary_run = BenchmarkCaseRunRecord.predeclared_excluded(
        benchmark_case_id=base.id,
        architecture=Architecture.ARM,
    )
    with pytest.raises(BenchmarkCaseAccountingError, match="excluded_unsupported"):
        BenchmarkEvaluationRunner().evaluate(
            _manifest([base]),
            [primary_run],
        )


def test_primary_unsupported_candidate_remains_in_strict_denominator() -> None:
    case = _case(_fixture_manifest(), BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    bundle = _bundle(
        case,
        feasibility_status=ChainFeasibilityStatus.UNSUPPORTED,
    )
    report = BenchmarkEvaluationRunner().evaluate(
        _manifest([case]),
        [BenchmarkCaseRunRecord.from_candidate(bundle)],
    )

    assert report.verification_hit_rate.denominator_ids == [bundle.candidate.id]
    assert report.verification_hit_rate.numerator == 0
    assert report.feasibility_status_counts[
        ChainFeasibilityStatus.UNSUPPORTED
    ] == 1


def test_recovery_counts_one_ground_truth_once_and_metric_can_be_undefined() -> None:
    manifest = _fixture_manifest()
    report = BenchmarkEvaluationRunner().evaluate(
        manifest,
        _owned_runs(manifest),
    )
    recovery = report.ground_truth_recoveries[0]

    assert isinstance(recovery, GroundTruthRecoveryRecord)
    assert recovery.recovered_candidate_ids == sorted(
        set(recovery.recovered_candidate_ids)
    )
    assert report.ground_truth_chain_recall.numerator == 1
    undefined = EvaluationMetricResult.create(
        metric_name=EvaluationMetricName.NEGATIVE_CONTROL_FALSE_POSITIVE_RATE,
        numerator_ids=[],
        denominator_ids=[],
    )
    assert undefined.defined is False
    assert undefined.ratio is None
    assert undefined.percentage is None


def test_confidence_metadata_and_input_order_do_not_change_report_identity() -> None:
    manifest = _fixture_manifest()
    runs = _owned_runs(manifest)
    first = BenchmarkEvaluationRunner().evaluate(manifest, runs)
    positive_run = next(
        item
        for item in runs
        if item.candidate_bundle is not None
        and item.candidate_bundle.candidate.benchmark_case_id
        == _case(manifest, BenchmarkCaseLabel.POSITIVE_FEASIBLE).id
    )
    assert positive_run.candidate_bundle is not None
    bundle = positive_run.candidate_bundle
    candidate_values = bundle.candidate.model_dump(mode="json")
    candidate_values["model_confidence"] = 0.91
    changed_candidate = FinalizedCandidateRecord.model_validate(candidate_values)
    changed_bundle = CandidateEvaluationBundle.create(
        candidate=changed_candidate,
        claim_binding=bundle.claim_binding,
        feasibility=bundle.feasibility,
        triggerability=bundle.triggerability,
        metadata={"fixture_note": "changed"},
    )
    assert changed_bundle.id == bundle.id
    changed_run = BenchmarkCaseRunRecord.from_candidate(
        changed_bundle,
        metadata={"fixture_note": "changed"},
    )
    changed_runs = [
        changed_run if item.id == positive_run.id else item for item in runs
    ]
    second = BenchmarkEvaluationRunner().evaluate(
        manifest,
        list(reversed(changed_runs)),
    )

    assert changed_candidate.id == bundle.candidate.id
    assert changed_run.id == positive_run.id
    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_json_roundtrip_tamper_rejection_and_failure_metadata_hygiene() -> None:
    manifest = _fixture_manifest()
    report = BenchmarkEvaluationRunner().evaluate(
        manifest,
        _owned_runs(manifest),
    )
    assert BenchmarkEvaluationReport.model_validate_json(
        report.model_dump_json()
    ) == report
    tampered = report.model_dump(mode="json")
    tampered["id"] = "benchmark-evaluation-report:tampered"
    with pytest.raises(ValidationError, match="not deterministic"):
        BenchmarkEvaluationReport.model_validate(tampered)

    negative = _case(manifest, BenchmarkCaseLabel.NEGATIVE_CONTROL)
    with pytest.raises(ValidationError, match="host paths|forbidden diagnostics"):
        BenchmarkCaseExecutionFailure.create(
            benchmark_case_id=negative.id,
            architecture=Architecture.ARM,
            stage=BenchmarkExecutionStage.CANDIDATE_FINALIZATION,
            failure_code=(
                BenchmarkExecutionFailureCode.CANDIDATE_FINALIZATION_FAILED
            ),
            metadata={"detail": "Traceback File /home/private/secret.py"},
        )


def test_mutated_case_run_is_revalidated_and_rejected() -> None:
    manifest = _fixture_manifest()
    run = _owned_runs(manifest)[0]
    run.__dict__["id"] = "benchmark-case-run:tampered"

    with pytest.raises(InvalidBenchmarkEvaluationInputError, match="revalidation"):
        BenchmarkEvaluationRunner().evaluate(manifest, [run])


def test_ground_truth_firewall_and_aggregation_only_runner_surface() -> None:
    ground_truth_free_paths = (
        ROOT / "src/chipchain/evaluation/candidate.py",
        ROOT / "src/chipchain/evaluation/claim_binding.py",
        ROOT / "src/chipchain/evaluation/oracle.py",
        ROOT / "src/chipchain/reasoning/parser.py",
    )
    for path in ground_truth_free_paths:
        tree = ast.parse(path.read_text("utf-8"))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        assert "GroundTruthChain" not in imported
        assert "BenchmarkManifest" not in imported

    parameters = inspect.signature(BenchmarkEvaluationRunner.evaluate).parameters
    assert list(parameters) == ["self", "manifest", "case_run_records"]
    runner_source = (
        ROOT / "src/chipchain/evaluation/runner.py"
    ).read_text("utf-8")
    for forbidden in (
        "ModelClaimBinder",
        "ChainFeasibilityOracle",
        "AgentWorkflow",
        "ReasoningProvider",
        "QEMU",
        "angr",
    ):
        assert forbidden not in runner_source


def test_report_creates_no_domain_truth_or_threshold_conclusion() -> None:
    manifest = _fixture_manifest()
    report = BenchmarkEvaluationRunner().evaluate(
        manifest,
        _owned_runs(manifest),
    )
    payload = report.model_dump(mode="json")
    serialized = json.dumps(payload).lower()

    assert not isinstance(report, AttackChain)
    assert not isinstance(report, VerificationRecord)
    assert "attackchain" not in serialized
    assert "verificationrecord" not in serialized
    assert "threshold_pass" not in serialized
    assert "threshold_result" not in serialized
    assert "project_performance_result" not in serialized
    assert payload["metadata"]["threshold_interpretation_performed"] is False
