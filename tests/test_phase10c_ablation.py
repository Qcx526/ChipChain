"""Offline Phase 10C prompt-firewall and deterministic ablation tests."""

from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.agents import AgentWorkflow, ProviderBackedAgentWorkflow, ReasoningContext
from chipchain.evaluation import (
    AblationComparisonBuilder,
    AblationConditionExecutionFailure,
    AblationConditionFailureCode,
    AblationConditionFailureStage,
    AblationConditionKind,
    AblationConditionResult,
    AblationConditionSpec,
    AblationExperimentPlan,
    AblationMetricDelta,
    BenchmarkCaseLabel,
    BenchmarkCaseRunRecord,
    BenchmarkEvaluationRunner,
    ChainFeasibilityStatus,
    ContextObjectiveUpperBoundEvaluator,
    ContextObjectiveUpperBoundRate,
    EvaluationMetricName,
    EvaluationMetricResult,
    FinalizedCandidateBuilder,
    ModelClaimBinder,
    ModelClaimBindingStatus,
    ObjectiveExperimentInputSourceSet,
    PromptVisibilityAuditStatus,
    PromptVisibilityAuditor,
    structured_prompt_request_sha256,
)
from chipchain.knowledge import (
    DeterministicKnowledgeRetriever,
    InMemoryKnowledgeEntryRepository,
    KnowledgeRetrievalQuery,
)
from chipchain.models import Architecture, CrossLayerInteraction, CrossLayerInteractionType, Layer
from chipchain.reasoning import (
    MockReasoningProvider,
    ReasoningAgentType,
    ReasoningEngine,
    ReasoningPromptView,
    ReasoningPromptVisibility,
    ReasoningProvider,
    RoleBasedReasoningPromptBuilder,
    StructuredPromptRequest,
    masked_chain_hidden_reference_ids,
)
from chipchain.runtime import RuntimeEventKind, RuntimeObservation
from chipchain.verification import ProgramAddress
from tests.test_phase10b_benchmark_evaluation import (
    _bundle,
    _case,
    _fixture_manifest,
    _manifest,
    _owned_runs,
)


ROOT = Path(__file__).resolve().parents[1]


def _interaction() -> CrossLayerInteraction:
    return CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
        source_layer=Layer.FIRMWARE,
        target_layer=Layer.HARDWARE,
        target_vulnerability_ids=["hidden-hw-vulnerability"],
        trigger_behavior_ids=["hidden-trigger-behavior"],
        hardware_resource_ids=["visible-hardware-resource"],
        referenced_architectures=[Architecture.ARM],
    )


def _context() -> ReasoningContext:
    return ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id="visible-subject-id",
        affected_components=["visible-driver", "visible-device"],
        observed_fact_ids=["visible-observed-fact"],
        available_evidence_ids=["visible-evidence-id"],
        dynamic_trigger_fact_reference="hidden-dynamic-trigger",
        attack_pattern_reference="hidden-attack-pattern",
        cross_layer_interaction=_interaction(),
        metadata={"fixture": True, "synthetic": True},
    )


def _prompt(visibility: ReasoningPromptVisibility) -> StructuredPromptRequest:
    return RoleBasedReasoningPromptBuilder().build(
        _context(), role=ReasoningAgentType.ATTACK_CHAIN, visibility=visibility
    )


def _reports_and_upper():
    manifest = _fixture_manifest()
    positive = _case(manifest, BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    negative = _case(manifest, BenchmarkCaseLabel.NEGATIVE_CONTROL)
    full_runs = _owned_runs(manifest)
    masked_runs = [
        BenchmarkCaseRunRecord.from_candidate(
            _bundle(
                positive,
                binding_status=ModelClaimBindingStatus.MISMATCHED,
            )
        ),
        full_runs[1],
    ]
    no_model_runs = [
        BenchmarkCaseRunRecord.from_candidate(
            _bundle(
                positive,
                binding_status=ModelClaimBindingStatus.MISSING,
            )
        ),
        BenchmarkCaseRunRecord.from_candidate(
            _bundle(
                negative,
                binding_status=ModelClaimBindingStatus.MISSING,
                feasibility_status=ChainFeasibilityStatus.UNRESOLVED,
            )
        ),
    ]
    runner = BenchmarkEvaluationRunner()
    return (
        manifest,
        runner.evaluate(manifest, full_runs),
        runner.evaluate(manifest, masked_runs),
        runner.evaluate(manifest, no_model_runs),
        ContextObjectiveUpperBoundEvaluator().evaluate(manifest, full_runs),
    )


def _condition_results():
    manifest, full, masked, no_model, upper = _reports_and_upper()
    plan = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    audit = PromptVisibilityAuditor.audit(
        _prompt(ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT),
        hidden_reference_ids=[_context().cross_layer_interaction.id],
    )
    results = [
        AblationConditionResult.create(
            ablation_plan_id=plan.id,
            condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
            benchmark_manifest_id=manifest.id,
            benchmark_evaluation_report=full,
        ),
        AblationConditionResult.create(
            ablation_plan_id=plan.id,
            condition_kind=AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
            benchmark_manifest_id=manifest.id,
            benchmark_evaluation_report=masked,
            prompt_visibility_audit_ids=[audit.id],
        ),
        AblationConditionResult.create(
            ablation_plan_id=plan.id,
            condition_kind=AblationConditionKind.NO_MODEL_BASELINE,
            benchmark_manifest_id=manifest.id,
            benchmark_evaluation_report=no_model,
        ),
        AblationConditionResult.create(
            ablation_plan_id=plan.id,
            condition_kind=AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND,
            benchmark_manifest_id=manifest.id,
            context_objective_upper_bound_result=upper,
        ),
    ]
    return plan, results


def test_full_default_prompt_is_byte_for_byte_backward_compatible() -> None:
    builder = RoleBasedReasoningPromptBuilder()
    implicit = builder.build(_context(), role=ReasoningAgentType.ATTACK_CHAIN)
    explicit = builder.build(
        _context(),
        role=ReasoningAgentType.ATTACK_CHAIN,
        visibility=ReasoningPromptVisibility.FULL_CONTEXT,
    )
    assert implicit == explicit
    assert hashlib.sha256(explicit.model_dump_json().encode()).hexdigest() == (
        "be5b3de8746e950045cb89531312dc47e0544c9702b6f16ab3676dcf6827f548"
    )
    legacy_reconstruction = builder.build_for_projection_contract(
        _context(),
        role=ReasoningAgentType.ATTACK_CHAIN,
        visibility=ReasoningPromptVisibility.FULL_CONTEXT,
        masked_prompt_projection_contract=None,
    )
    assert legacy_reconstruction == explicit


def test_collision_free_masked_prompt_is_byte_compatible() -> None:
    prompt = _prompt(ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT)

    assert hashlib.sha256(prompt.model_dump_json().encode()).hexdigest() == (
        "e36696c939799dd99dab11948d61bdcbe54f677c4530cd065cd8b0f38967ba86"
    )


def test_masked_view_is_deterministic_and_input_order_neutral() -> None:
    first = ReasoningPromptView.create(
        _context(), visibility=ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT
    )
    values = _context().model_dump(mode="json")
    values["affected_components"].reverse()
    altered = ReasoningContext.create(
        architecture=values["architecture"],
        subject_id=values["subject_id"],
        affected_components=values["affected_components"],
        observed_fact_ids=values["observed_fact_ids"],
        available_evidence_ids=values["available_evidence_ids"],
        dynamic_trigger_fact_reference=values["dynamic_trigger_fact_reference"],
        attack_pattern_reference=values["attack_pattern_reference"],
        cross_layer_interaction=_interaction(),
    )
    second = ReasoningPromptView.create(
        altered, visibility=ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT
    )
    assert first == second
    assert second == ReasoningPromptView.create(
        altered, visibility=ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT
    )


@pytest.mark.parametrize(
    "hidden",
    [
        lambda context: context.id,
        lambda context: context.cross_layer_interaction.id,
        lambda context: context.cross_layer_interaction.target_vulnerability_ids[0],
        lambda context: context.cross_layer_interaction.trigger_behavior_ids[0],
        lambda context: context.attack_pattern_reference,
        lambda context: context.dynamic_trigger_fact_reference,
    ],
)
def test_masked_prompt_hides_chain_answer_references(hidden) -> None:
    context = _context()
    prompt = _prompt(ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT)
    assert hidden(context) not in prompt.system_prompt + prompt.user_prompt
    assert json.loads(prompt.user_prompt)["reasoning_context"]["id"].startswith(
        "reasoning-prompt-view:"
    )


@pytest.mark.parametrize(
    "visible",
    ["visible-subject-id", "visible-driver", "visible-observed-fact", "visible-evidence-id"],
)
def test_masked_prompt_retains_non_chain_facts(visible: str) -> None:
    assert visible in _prompt(ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT).user_prompt


def test_hidden_reference_policy_is_centralized_deterministic_and_exact() -> None:
    context = _context()
    expected = sorted(
        {
            context.attack_pattern_reference,
            context.dynamic_trigger_fact_reference,
            context.cross_layer_interaction.id,
            *context.cross_layer_interaction.target_vulnerability_ids,
            *context.cross_layer_interaction.trigger_behavior_ids,
            *context.cross_layer_interaction.hardware_resource_ids,
        }
    )

    assert masked_chain_hidden_reference_ids(context) == expected
    assert masked_chain_hidden_reference_ids(context) == expected
    assert Architecture.ARM.value not in expected


def test_owned_step6_collision_is_removed_and_same_policy_audits_pass() -> None:
    source_set = ObjectiveExperimentInputSourceSet.model_validate_json(
        (
            ROOT
            / "tests/fixtures/evaluation/phase10d_owned_objective_inputs.json"
        ).read_text(encoding="utf-8")
    )
    context = next(
        item.reasoning_context
        for item in source_set.case_sources
        if item.triggerability_source is not None
    )
    hidden = masked_chain_hidden_reference_ids(context)
    masked_view = ReasoningPromptView.create(
        context,
        visibility=ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
    )
    masked_prompt = RoleBasedReasoningPromptBuilder().build(
        context,
        role=ReasoningAgentType.CODE,
        visibility=ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
    )
    full_prompt = RoleBasedReasoningPromptBuilder().build(
        context,
        role=ReasoningAgentType.CODE,
        visibility=ReasoningPromptVisibility.FULL_CONTEXT,
    )
    legacy_prompt = RoleBasedReasoningPromptBuilder().build_for_projection_contract(
        context,
        role=ReasoningAgentType.CODE,
        visibility=ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
        masked_prompt_projection_contract=None,
    )
    audit = PromptVisibilityAuditor.audit(
        masked_prompt,
        hidden_reference_ids=hidden,
    )

    assert "synthetic-owned-arm-execution-core" in hidden
    assert masked_view.affected_components == [
        "synthetic-owned-arm-firmware"
    ]
    assert "synthetic-owned-arm-execution-core" not in masked_prompt.user_prompt
    assert audit.status is PromptVisibilityAuditStatus.PASS
    assert audit.leaked_reference_ids == []
    assert "synthetic-owned-arm-execution-core" in full_prompt.user_prompt
    assert structured_prompt_request_sha256(legacy_prompt) == (
        "0934f36721272491e532a18d44467ac0e24aa118c1f5acdf4c285bc61311a341"
    )
    assert structured_prompt_request_sha256(legacy_prompt) != (
        structured_prompt_request_sha256(masked_prompt)
    )
    assert "synthetic-owned-arm-execution-core" in legacy_prompt.user_prompt
    legacy_payload = json.loads(legacy_prompt.user_prompt)
    assert legacy_payload["provider_authority"][
        "supporting_evidence_ids_allowed_values"
    ] == context.available_evidence_ids


def test_masked_reconstruction_rejects_unknown_projection_contract() -> None:
    with pytest.raises(ValueError, match="unsupported masked prompt projection"):
        RoleBasedReasoningPromptBuilder().build_for_projection_contract(
            _context(),
            role=ReasoningAgentType.CODE,
            visibility=ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
            masked_prompt_projection_contract="fixture-unknown-projection",
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "affected_components",
        "observed_fact_ids",
        "available_evidence_ids",
        "knowledge_entry_ids",
    ],
)
def test_masked_projection_filters_cross_field_substring_collisions(
    field_name: str,
) -> None:
    hidden = "hidden-trigger-behavior"
    values = {
        "affected_components": ["visible-component"],
        "observed_fact_ids": ["visible-observed-fact"],
        "available_evidence_ids": ["visible-evidence"],
        "knowledge_entry_ids": ["visible-knowledge"],
    }
    values[field_name] = [f"prefix:{hidden}:suffix", f"visible-{field_name}"]
    context = ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id="visible-subject",
        cross_layer_interaction=_interaction(),
        **values,
    )
    prompt = RoleBasedReasoningPromptBuilder().build(
        context,
        role=ReasoningAgentType.CODE,
        visibility=ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
    )
    payload = json.loads(prompt.user_prompt)
    legacy_prompt = RoleBasedReasoningPromptBuilder().build_for_projection_contract(
        context,
        role=ReasoningAgentType.CODE,
        visibility=ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
        masked_prompt_projection_contract=None,
    )
    legacy_payload = json.loads(legacy_prompt.user_prompt)

    assert hidden not in prompt.user_prompt
    assert legacy_payload["reasoning_context"][field_name] == sorted(
        values[field_name]
    )
    if field_name == "available_evidence_ids":
        assert payload["reasoning_context"][field_name] == [
            "visible-available_evidence_ids"
        ]
        assert payload["provider_authority"][
            "supporting_evidence_ids_allowed_values"
        ] == ["visible-available_evidence_ids"]
        assert legacy_payload["provider_authority"][
            "supporting_evidence_ids_allowed_values"
        ] == sorted(values[field_name])


def test_masked_projection_rejects_subject_and_all_component_collisions() -> None:
    hidden = "hidden-trigger-behavior"
    common = {
        "architecture": Architecture.ARM,
        "cross_layer_interaction": _interaction(),
    }
    subject_collision = ReasoningContext.create(
        **common,
        subject_id=f"subject:{hidden}",
        affected_components=["visible-component"],
    )
    component_collision = ReasoningContext.create(
        **common,
        subject_id="visible-subject",
        affected_components=[f"component:{hidden}"],
    )

    class CountingProvider(ReasoningProvider):
        def __init__(self) -> None:
            self.calls = 0

        def generate(self, request: StructuredPromptRequest) -> str:
            self.calls += 1
            return MockReasoningProvider().generate(request)

    for context, message in (
        (subject_collision, "subject ID collides"),
        (component_collision, "non-hidden affected component"),
    ):
        provider = CountingProvider()
        engine = ReasoningEngine(
            provider=provider,
            prompt_visibility=(
                ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT
            ),
        )
        with pytest.raises(ValueError, match=message):
            engine.reason(context, role=ReasoningAgentType.CODE)
        assert provider.calls == 0


def test_masked_projection_omits_whole_colliding_nested_objects() -> None:
    hidden = "hidden-trigger-behavior"
    observation = RuntimeObservation.create(
        trace_id=f"trace:{hidden}",
        architecture=Architecture.ARM,
        sequence_index=0,
        vcpu_index=0,
        event_kind=RuntimeEventKind.INSTRUCTION_EXEC,
        pc=ProgramAddress(value="0x1000"),
    )
    query = KnowledgeRetrievalQuery.create(
        architecture=Architecture.ARM,
        text=f"lookup {hidden}",
    )
    knowledge = DeterministicKnowledgeRetriever(
        InMemoryKnowledgeEntryRepository([])
    ).retrieve(query)
    context = ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id="visible-subject",
        affected_components=["visible-component"],
        cross_layer_interaction=_interaction(),
        runtime_observations=[observation],
        knowledge_retrieval_result=knowledge,
    )
    view = ReasoningPromptView.create(
        context,
        visibility=ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
    )
    legacy_prompt = RoleBasedReasoningPromptBuilder().build_for_projection_contract(
        context,
        role=ReasoningAgentType.CODE,
        visibility=ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
        masked_prompt_projection_contract=None,
    )
    legacy_context = json.loads(legacy_prompt.user_prompt)["reasoning_context"]

    assert view.runtime_observations == []
    assert view.knowledge_retrieval_result is None
    assert legacy_context["runtime_observations"] == [
        item.model_dump(mode="json") for item in context.runtime_observations
    ]
    assert legacy_context["knowledge_retrieval_result"] == (
        context.knowledge_retrieval_result.model_dump(mode="json")
    )
    assert context.runtime_observations == [observation]
    assert context.knowledge_retrieval_result is not None
    assert "<hidden>" not in json.dumps(view.visible_context())


def test_full_prompt_is_intentional_chain_context_control() -> None:
    prompt = _prompt(ReasoningPromptVisibility.FULL_CONTEXT)
    context = _context()
    for value in (
        context.id,
        context.cross_layer_interaction.id,
        "hidden-hw-vulnerability",
        "hidden-trigger-behavior",
        "hidden-attack-pattern",
        "hidden-dynamic-trigger",
    ):
        assert value in prompt.user_prompt


class _WrongMaskedClaimProvider(ReasoningProvider):
    def generate(self, request: StructuredPromptRequest) -> str:
        payload = json.loads(MockReasoningProvider().generate(request))
        if request.role == ReasoningAgentType.ATTACK_CHAIN.value:
            payload["hypothesis"]["chain_claim"] = {
                "interaction_type": "firmware_behavior_to_hardware",
                "initiating_vulnerability_ids": [],
                "target_vulnerability_ids": ["wrong-model-target"],
                "trigger_behavior_ids": ["wrong-model-trigger"],
                "propagation_behavior_ids": [],
                "affected_execution_ids": [],
                "fault_state_ids": [],
                "hardware_resource_ids": [],
                "security_mechanism_ids": [],
            }
        return json.dumps(payload, sort_keys=True)


def test_masked_workflow_retains_full_context_and_does_not_repair_claim() -> None:
    context = _context()
    session = ProviderBackedAgentWorkflow(
        engine=ReasoningEngine(
            provider=_WrongMaskedClaimProvider(),
            prompt_visibility=ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
        )
    ).execute(context)
    candidate = FinalizedCandidateBuilder.from_reasoning_session(
        "fixture-phase10c-case", session
    )
    assessment = ModelClaimBinder().assess(candidate, context.cross_layer_interaction)
    assert session.reasoning_context.cross_layer_interaction == context.cross_layer_interaction
    assert candidate.model_authored_chain_claim.target_vulnerability_ids == [
        "wrong-model-target"
    ]
    assert "hidden-hw-vulnerability" not in candidate.model_authored_chain_claim.target_vulnerability_ids
    assert assessment.status is ModelClaimBindingStatus.MISMATCHED


def test_parser_uses_full_context_for_system_owned_bindings() -> None:
    hypothesis, _, _ = ReasoningEngine(
        provider=MockReasoningProvider(),
        prompt_visibility=ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
    ).reason(_context(), role=ReasoningAgentType.CODE)
    assert hypothesis.affected_components == _context().affected_components
    assert hypothesis.attack_pattern_reference == "hidden-attack-pattern"
    assert hypothesis.model_authored_chain_claim is None


def test_no_model_baseline_keeps_candidate_and_missing_claim() -> None:
    context = _context()
    session = AgentWorkflow().execute(context)
    candidate = FinalizedCandidateBuilder.from_reasoning_session(
        "fixture-phase10c-no-model", session
    )
    assert candidate.model_authored_chain_claim is None
    assert ModelClaimBinder().assess(
        candidate, context.cross_layer_interaction
    ).status is ModelClaimBindingStatus.MISSING


def test_owned_phase10b_result_remains_one_of_two() -> None:
    manifest = _fixture_manifest()
    report = BenchmarkEvaluationRunner().evaluate(manifest, _owned_runs(manifest))
    assert (report.verification_hit_rate.numerator, report.verification_hit_rate.denominator) == (1, 2)


def test_context_upper_bound_ignores_only_claim_gate() -> None:
    manifest = _fixture_manifest()
    positive = _case(manifest, BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    negative = _case(manifest, BenchmarkCaseLabel.NEGATIVE_CONTROL)
    runs = [
        BenchmarkCaseRunRecord.from_candidate(
            _bundle(positive, binding_status=ModelClaimBindingStatus.MISSING)
        ),
        BenchmarkCaseRunRecord.from_candidate(
            _bundle(
                negative,
                binding_status=ModelClaimBindingStatus.MISSING,
                feasibility_status=ChainFeasibilityStatus.UNRESOLVED,
            )
        ),
    ]
    result = ContextObjectiveUpperBoundEvaluator().evaluate(manifest, runs)
    report = BenchmarkEvaluationRunner().evaluate(manifest, runs)
    assert (result.rate.numerator, result.rate.denominator) == (1, 2)
    assert report.verification_hit_rate.numerator == 0
    assert result.rate.id.startswith("context-objective-upper-bound-rate:")


@pytest.mark.parametrize("cohort", ["numerator_ids", "denominator_ids"])
def test_upper_bound_persisted_duplicate_cohort_fails_closed(cohort: str) -> None:
    rate = ContextObjectiveUpperBoundRate.create(
        numerator_ids=["candidate-a"],
        denominator_ids=["candidate-a", "candidate-b"],
    )
    values = rate.model_dump(mode="json")
    values[cohort] = ["candidate-a", "candidate-a"]
    values["numerator" if cohort == "numerator_ids" else "denominator"] = 2

    with pytest.raises(ValidationError, match="must be unique"):
        ContextObjectiveUpperBoundRate.model_validate(values)


def test_upper_bound_persisted_numerator_cannot_exceed_denominator() -> None:
    rate = ContextObjectiveUpperBoundRate.create(
        numerator_ids=["candidate-a"],
        denominator_ids=["candidate-a", "candidate-b"],
    )
    values = rate.model_dump(mode="json")
    values.update(
        numerator=2,
        numerator_ids=["candidate-a", "candidate-b"],
        denominator=1,
        denominator_ids=["candidate-a"],
    )

    with pytest.raises(ValidationError):
        ContextObjectiveUpperBoundRate.model_validate(values)


def test_upper_bound_persisted_unique_cohort_normalizes_without_identity_drift() -> None:
    canonical = ContextObjectiveUpperBoundRate.create(
        numerator_ids=["candidate-a"],
        denominator_ids=["candidate-a", "candidate-b"],
    )
    values = canonical.model_dump(mode="json")
    values["denominator_ids"] = ["candidate-b", "candidate-a"]

    restored = ContextObjectiveUpperBoundRate.model_validate_json(
        json.dumps(values)
    )

    assert restored.denominator_ids == ["candidate-a", "candidate-b"]
    assert restored.id == canonical.id
    assert (restored.numerator, restored.denominator, restored.ratio) == (1, 2, 0.5)


def test_upper_bound_zero_denominator_remains_undefined_not_zero_percent() -> None:
    rate = ContextObjectiveUpperBoundRate.create(
        numerator_ids=[], denominator_ids=[]
    )

    assert (rate.numerator, rate.denominator) == (0, 0)
    assert rate.defined is False
    assert rate.ratio is None


@pytest.mark.parametrize(
    ("feasibility", "expected"),
    [
        (ChainFeasibilityStatus.CONFIRMED_FEASIBLE, 1),
        (ChainFeasibilityStatus.UNRESOLVED, 0),
        (ChainFeasibilityStatus.NOT_SUPPORTED, 0),
    ],
)
def test_upper_bound_still_requires_confirmed_feasibility(feasibility, expected) -> None:
    manifest = _fixture_manifest()
    positive = _case(manifest, BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    negative = _case(manifest, BenchmarkCaseLabel.NEGATIVE_CONTROL)
    runs = [
        BenchmarkCaseRunRecord.from_candidate(
            _bundle(positive, feasibility_status=feasibility)
        ),
        BenchmarkCaseRunRecord.from_candidate(
            _bundle(
                negative,
                binding_status=ModelClaimBindingStatus.MISSING,
                feasibility_status=ChainFeasibilityStatus.UNRESOLVED,
            )
        ),
    ]
    assert ContextObjectiveUpperBoundEvaluator().evaluate(manifest, runs).rate.numerator == expected


def test_upper_bound_requires_exact_ground_truth_and_rejects_negative_hit() -> None:
    manifest = _fixture_manifest()
    positive = _case(manifest, BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    negative = _case(manifest, BenchmarkCaseLabel.NEGATIVE_CONTROL)
    wrong = CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
        source_layer=Layer.FIRMWARE,
        target_layer=Layer.HARDWARE,
        target_vulnerability_ids=["wrong-ground-truth-target"],
        trigger_behavior_ids=["wrong-ground-truth-trigger"],
        hardware_resource_ids=["wrong-resource"],
        referenced_architectures=[Architecture.ARM],
    )
    runs = [
        BenchmarkCaseRunRecord.from_candidate(_bundle(positive, interaction=wrong)),
        BenchmarkCaseRunRecord.from_candidate(
            _bundle(negative, feasibility_status=ChainFeasibilityStatus.CONFIRMED_FEASIBLE)
        ),
    ]
    result = ContextObjectiveUpperBoundEvaluator().evaluate(manifest, runs)
    assert result.rate.numerator == 0
    assert result.rate.denominator == 2


def test_prompt_leakage_audit_detects_exact_leak_and_is_non_interfering() -> None:
    prompt = _prompt(ReasoningPromptVisibility.FULL_CONTEXT)
    before = prompt.model_dump_json()
    leaked = PromptVisibilityAuditor.audit(
        prompt, hidden_reference_ids=["hidden-hw-vulnerability"]
    )
    clean = PromptVisibilityAuditor.audit(
        prompt, hidden_reference_ids=["not-present-hidden-reference"]
    )
    assert leaked.status is PromptVisibilityAuditStatus.LEAK_DETECTED
    assert leaked.leaked_reference_ids == ["hidden-hw-vulnerability"]
    assert clean.status is PromptVisibilityAuditStatus.PASS
    assert prompt.model_dump_json() == before


def test_plan_has_exact_deterministic_four_condition_set() -> None:
    manifest = _fixture_manifest()
    first = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id, benchmark_version=manifest.benchmark_version
    )
    second = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
        metadata={"different": "neutral"},
    )
    assert first.id == second.id
    assert {item.condition_kind for item in first.condition_specs} == set(AblationConditionKind)
    assert all(item.repetitions == 1 for item in first.condition_specs)


@pytest.mark.parametrize(
    "field",
    ["prompt_visibility", "requires_model_provider", "uses_model_claim_gate", "uses_context_objective_upper_bound", "repetitions"],
)
def test_contradictory_condition_configuration_is_rejected(field: str) -> None:
    spec = AblationConditionSpec.create(AblationConditionKind.FULL_CONTEXT_MODEL)
    values = spec.model_dump(mode="json")
    values[field] = 2 if field == "repetitions" else (
        "masked_chain_context" if field == "prompt_visibility" else not values[field]
    )
    with pytest.raises(ValidationError):
        AblationConditionSpec.model_validate(values)


def test_comparison_accounts_all_conditions_and_exact_deltas() -> None:
    plan, results = _condition_results()
    report = AblationComparisonBuilder.compare(plan, list(reversed(results)))
    assert len(report.condition_results) == 4
    assert report.coverage_comparable is True
    assert report.full_minus_masked_delta.delta == 0.5
    assert report.full_minus_no_model_delta.delta == 0.5
    assert report.upper_bound_minus_full_delta.delta == 0.0
    assert set(report.coverage_by_condition) == {
        AblationConditionKind.FULL_CONTEXT_MODEL,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        AblationConditionKind.NO_MODEL_BASELINE,
    }


def test_condition_failure_cannot_disappear_and_makes_delta_undefined() -> None:
    plan, results = _condition_results()
    failure = AblationConditionExecutionFailure.create(
        ablation_plan_id=plan.id,
        condition_kind=AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        stage=AblationConditionFailureStage.PROVIDER,
        failure_code=AblationConditionFailureCode.PROVIDER_UNAVAILABLE,
    )
    results[1] = AblationConditionResult.create(
        ablation_plan_id=plan.id,
        condition_kind=AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        benchmark_manifest_id=plan.benchmark_manifest_id,
        execution_failure=failure,
    )
    report = AblationComparisonBuilder.compare(plan, results)
    assert report.masked_context_verification_hit_rate is None
    assert report.full_minus_masked_delta.defined is False
    assert (
        report.full_minus_masked_delta.left_metric_id
        == report.full_context_verification_hit_rate.id
    )
    assert (
        report.full_minus_masked_delta.right_metric_id,
        report.full_minus_masked_delta.right_numerator,
        report.full_minus_masked_delta.right_denominator,
    ) == (None, None, None)
    assert report.coverage_comparable is False


def test_missing_declared_condition_is_rejected() -> None:
    plan, results = _condition_results()
    with pytest.raises(ValueError, match="all predeclared"):
        AblationComparisonBuilder.compare(plan, results[:-1])


def test_same_manifest_and_scope_are_required() -> None:
    manifest = _fixture_manifest()
    positive = _case(manifest, BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    other_manifest = _manifest([positive])
    other_report = BenchmarkEvaluationRunner().evaluate(
        other_manifest,
        [BenchmarkCaseRunRecord.from_candidate(_bundle(positive))],
    )
    plan = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id, benchmark_version=manifest.benchmark_version
    )
    with pytest.raises(ValidationError, match="manifest mismatch"):
        AblationConditionResult.create(
            ablation_plan_id=plan.id,
            condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
            benchmark_manifest_id=manifest.id,
            benchmark_evaluation_report=other_report,
        )


def test_metric_delta_uses_exact_components_and_undefined_state() -> None:
    left = EvaluationMetricResult.create(
        metric_name=EvaluationMetricName.VERIFICATION_HIT_RATE,
        numerator_ids=["candidate-a"],
        denominator_ids=["candidate-a", "candidate-b", "candidate-c"],
    )
    right = EvaluationMetricResult.create(
        metric_name=EvaluationMetricName.VERIFICATION_HIT_RATE,
        numerator_ids=["candidate-a"],
        denominator_ids=["candidate-a", "candidate-b"],
    )
    delta = AblationMetricDelta.create(left, right)
    assert (delta.left_numerator, delta.left_denominator) == (1, 3)
    assert (delta.right_numerator, delta.right_denominator) == (1, 2)
    assert delta.delta == pytest.approx(-1 / 6)
    absent = AblationMetricDelta.create(left, None)
    assert absent.delta is None
    assert absent.left_metric_id == left.id
    assert (absent.left_numerator, absent.left_denominator) == (1, 3)
    assert (
        absent.right_metric_id,
        absent.right_numerator,
        absent.right_denominator,
    ) == (None, None, None)


def test_undefined_metric_delta_retains_both_source_metrics() -> None:
    defined = EvaluationMetricResult.create(
        metric_name=EvaluationMetricName.VERIFICATION_HIT_RATE,
        numerator_ids=["candidate-a"],
        denominator_ids=["candidate-a", "candidate-b"],
    )
    undefined = EvaluationMetricResult.create(
        metric_name=EvaluationMetricName.GROUND_TRUTH_CHAIN_RECALL,
        numerator_ids=[],
        denominator_ids=[],
    )

    delta = AblationMetricDelta.create(defined, undefined)

    assert delta.defined is False
    assert delta.delta is None
    assert delta.left_metric_id == defined.id
    assert delta.right_metric_id == undefined.id
    assert (delta.right_numerator, delta.right_denominator) == (0, 0)


def test_distinct_undefined_source_comparisons_have_distinct_delta_ids() -> None:
    defined = EvaluationMetricResult.create(
        metric_name=EvaluationMetricName.VERIFICATION_HIT_RATE,
        numerator_ids=["candidate-a"],
        denominator_ids=["candidate-a"],
    )
    undefined_recall = EvaluationMetricResult.create(
        metric_name=EvaluationMetricName.GROUND_TRUTH_CHAIN_RECALL,
        numerator_ids=[],
        denominator_ids=[],
    )
    undefined_fpr = EvaluationMetricResult.create(
        metric_name=EvaluationMetricName.NEGATIVE_CONTROL_FALSE_POSITIVE_RATE,
        numerator_ids=[],
        denominator_ids=[],
    )

    first = AblationMetricDelta.create(defined, undefined_recall)
    second = AblationMetricDelta.create(defined, undefined_fpr)

    assert first.id != second.id
    assert first.right_metric_id != second.right_metric_id


def test_delta_cannot_claim_undefined_for_two_defined_sources() -> None:
    metric = EvaluationMetricResult.create(
        metric_name=EvaluationMetricName.VERIFICATION_HIT_RATE,
        numerator_ids=["candidate-a"],
        denominator_ids=["candidate-a", "candidate-b"],
    )
    values = AblationMetricDelta.create(metric, metric).model_dump(mode="json")
    values["defined"] = False

    with pytest.raises(ValidationError, match="defined state is inexact"):
        AblationMetricDelta.model_validate(values)


def test_delta_partial_side_fails_closed() -> None:
    metric = EvaluationMetricResult.create(
        metric_name=EvaluationMetricName.VERIFICATION_HIT_RATE,
        numerator_ids=[],
        denominator_ids=[],
    )
    values = AblationMetricDelta.create(metric, None).model_dump(mode="json")
    values.update(
        right_metric_id="evaluation-metric-result:partial",
        right_numerator=None,
        right_denominator=0,
    )

    with pytest.raises(ValidationError, match="all-or-none"):
        AblationMetricDelta.model_validate(values)


def test_delta_present_side_numerator_cannot_exceed_denominator() -> None:
    metric = EvaluationMetricResult.create(
        metric_name=EvaluationMetricName.VERIFICATION_HIT_RATE,
        numerator_ids=["candidate-a"],
        denominator_ids=["candidate-a", "candidate-b"],
    )
    values = AblationMetricDelta.create(metric, None).model_dump(mode="json")
    values["left_numerator"] = 3

    with pytest.raises(ValidationError, match="invalid rational components"):
        AblationMetricDelta.model_validate(values)


def test_ablation_contracts_json_roundtrip_and_tampered_ids_fail_closed() -> None:
    plan, results = _condition_results()
    report = AblationComparisonBuilder.compare(plan, results)
    assert type(report).model_validate_json(report.model_dump_json()) == report
    values = report.model_dump(mode="json")
    values["id"] = "ablation-comparison-report:tampered"
    with pytest.raises(ValidationError, match="not deterministic"):
        type(report).model_validate(values)


def test_metadata_is_identity_neutral_and_result_order_is_neutral() -> None:
    plan, results = _condition_results()
    first = AblationComparisonBuilder.compare(plan, results)
    second = AblationComparisonBuilder.compare(
        plan, list(reversed(results)), metadata={"fixture_note": "neutral"}
    )
    assert first.id == second.id


def test_ground_truth_types_cannot_enter_prompt_view_or_builder_contracts() -> None:
    prompt_signature = inspect.signature(RoleBasedReasoningPromptBuilder.build)
    view_signature = inspect.signature(ReasoningPromptView.create)
    forbidden = {"manifest", "benchmark_case", "ground_truth", "ground_truth_chain"}
    assert forbidden.isdisjoint(prompt_signature.parameters)
    assert forbidden.isdisjoint(view_signature.parameters)


def test_no_threshold_gate_and_no_real_provider_required() -> None:
    plan, results = _condition_results()
    report = AblationComparisonBuilder.compare(plan, results)
    serialized = json.dumps(report.model_dump(mode="json")).lower()
    assert '"threshold_interpretation_performed": false' in serialized
    assert "threshold_pass" not in serialized
    assert "project_conclusion" not in serialized
    assert report.full_context_verification_hit_rate.denominator == 2
