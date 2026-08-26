"""Offline Phase 10D Step 1 real-model experiment provenance tests."""

from __future__ import annotations

import inspect
import json

import pytest
from pydantic import ValidationError

from chipchain.agents import AgentWorkflow, ReasoningContext
from chipchain.evaluation import (
    AblationComparisonBuilder,
    AblationConditionExecutionFailure,
    AblationConditionFailureCode,
    AblationConditionFailureStage,
    AblationConditionKind,
    AblationExperimentPlan,
    ExperimentCaseInvocationKey,
    ExperimentExecutionMode,
    ModelInvocationDisposition,
    ModelInvocationRecord,
    PHASE10D_PROVIDER_ROLE_ORDER,
    PromptVisibilityAuditStatus,
    PromptVisibilityAuditor,
    RealExperimentConditionRecord,
    RealModelExperimentArtifact,
    RealModelExperimentPlan,
    RealModelInvocationFailure,
    RealModelInvocationFailureCode,
    RealModelInvocationFailureStage,
    RealModelProviderDescriptor,
    expected_experiment_invocation_keys,
    real_experiment_condition_record_id,
    structured_prompt_request_sha256,
    provider_response_sha256,
)
from chipchain.reasoning import (
    LLMAPIStyle,
    ReasoningAgentType,
    ReasoningPromptVisibility,
    RoleBasedReasoningPromptBuilder,
)
from chipchain.reasoning.models import LLMProviderConfig
from tests.test_phase10b_benchmark_evaluation import (
    _case,
    _fixture_manifest,
    _manifest,
)
from tests.test_phase10c_ablation import (
    _condition_results,
    _interaction,
    _reports_and_upper,
)


def _config(
    *,
    base_url: str = "https://fixture-provider.invalid/v1",
    model: str = "fixture-model-v1",
    api_style: LLMAPIStyle = LLMAPIStyle.CHAT_COMPLETIONS,
    json_mode: bool = True,
    timeout: float = 30.0,
    reasoning_effort: str | None = "low",
    max_completion_tokens: int | None = 512,
) -> LLMProviderConfig:
    return LLMProviderConfig(
        base_url=base_url,
        model=model,
        api_style=api_style,
        json_mode=json_mode,
        timeout=timeout,
        reasoning_effort=reasoning_effort,
        max_completion_tokens=max_completion_tokens,
    )


def _descriptor(**changes) -> RealModelProviderDescriptor:
    return RealModelProviderDescriptor.from_provider_config(
        _config(**changes)
    )


def _plan(
    *,
    descriptor: RealModelProviderDescriptor | None = None,
    metadata: dict[str, object] | None = None,
) -> RealModelExperimentPlan:
    manifest = _fixture_manifest()
    ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    return RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=ablation,
        provider_descriptor=descriptor or _descriptor(),
        execution_mode=ExperimentExecutionMode.OFFLINE_CONTRACT,
        metadata=metadata,
    )


def _one_case_plan() -> RealModelExperimentPlan:
    manifest = _manifest([_fixture_manifest().cases[0]])
    ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    return RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=ablation,
        provider_descriptor=_descriptor(),
        execution_mode=ExperimentExecutionMode.OFFLINE_CONTRACT,
    )


def _prompt(
    case_id: str,
    visibility: ReasoningPromptVisibility,
    role: ReasoningAgentType = ReasoningAgentType.ATTACK_CHAIN,
):
    context = ReasoningContext.create(
        architecture="arm",
        subject_id=f"fixture-phase10d-subject-{case_id}",
        affected_components=["fixture-driver", "fixture-device"],
        observed_fact_ids=[f"fixture-observed-{case_id}"],
        available_evidence_ids=[f"fixture-evidence-{case_id}"],
        dynamic_trigger_fact_reference="fixture-hidden-dynamic-trigger",
        attack_pattern_reference="fixture-hidden-attack-pattern",
        cross_layer_interaction=_interaction(),
        metadata={"fixture": True, "synthetic": True},
    )
    return RoleBasedReasoningPromptBuilder().build(
        context,
        role=role,
        visibility=visibility,
    )


def _invocations(
    plan: RealModelExperimentPlan,
    condition: AblationConditionKind,
) -> tuple[list[ModelInvocationRecord], list]:
    visibility = (
        ReasoningPromptVisibility.FULL_CONTEXT
        if condition is AblationConditionKind.FULL_CONTEXT_MODEL
        else ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT
    )
    records = []
    audits = []
    for case_id in plan.case_ids:
        for role in PHASE10D_PROVIDER_ROLE_ORDER:
            key = ExperimentCaseInvocationKey.create(
                plan,
                condition_kind=condition,
                benchmark_case_id=case_id,
                role=role,
            )
            prompt = _prompt(case_id, visibility, role)
            records.append(
                ModelInvocationRecord.completed(
                    plan,
                    key,
                    prompt=prompt,
                    raw_provider_response=(
                        f'{{"fixture":"{condition.value}:{case_id}:{role.value}"}}'
                    ),
                    metadata={"fixture": True, "offline_contract": True},
                )
            )
            if condition is AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL:
                audits.append(
                    PromptVisibilityAuditor.audit(
                        prompt,
                        hidden_reference_ids=[
                            _interaction().id,
                            "hidden-hw-vulnerability",
                            "hidden-trigger-behavior",
                            "fixture-hidden-attack-pattern",
                            "fixture-hidden-dynamic-trigger",
                        ],
                        metadata={"fixture": True},
                    )
                )
    return records, audits


def _fail_stop_invocations(
    plan: RealModelExperimentPlan,
    condition: AblationConditionKind,
    *,
    failed_case_id: str,
    failed_role: ReasoningAgentType,
    failure_stage: RealModelInvocationFailureStage = (
        RealModelInvocationFailureStage.PROVIDER_TRANSPORT
    ),
    prompt_available: bool = True,
    response_available: bool = False,
) -> tuple[list[ModelInvocationRecord], list]:
    records, audits = _invocations(plan, condition)
    visibility = (
        ReasoningPromptVisibility.FULL_CONTEXT
        if condition is AblationConditionKind.FULL_CONTEXT_MODEL
        else ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT
    )
    failed_index = PHASE10D_PROVIDER_ROLE_ORDER.index(failed_role)
    replacements: dict[str, ModelInvocationRecord] = {}
    for role_index, role in enumerate(PHASE10D_PROVIDER_ROLE_ORDER):
        key = ExperimentCaseInvocationKey.create(
            plan,
            condition_kind=condition,
            benchmark_case_id=failed_case_id,
            role=role,
        )
        if role_index < failed_index:
            continue
        if role is failed_role:
            failure = RealModelInvocationFailure.create(
                key,
                stage=failure_stage,
                failure_code=(
                    RealModelInvocationFailureCode.PROVIDER_CONTRACT_REJECTED
                    if failure_stage
                    is RealModelInvocationFailureStage.STRUCTURED_PARSE
                    else RealModelInvocationFailureCode.PROVIDER_TIMEOUT
                ),
            )
            prompt = (
                _prompt(failed_case_id, visibility, role)
                if prompt_available
                else None
            )
            replacements[key.id] = ModelInvocationRecord.failed(
                plan,
                key,
                failure=failure,
                prompt=prompt,
                raw_provider_response=(
                    '{"fixture":"invalid-structured-output"}'
                    if response_available
                    else None
                ),
            )
        else:
            replacements[key.id] = ModelInvocationRecord.not_attempted(
                plan,
                key,
                blocked_by_role=failed_role,
            )
    result = [replacements.get(item.invocation_key.id, item) for item in records]
    retained_prompt_hashes = {
        item.prompt_sha256 for item in result if item.prompt_sha256 is not None
    }
    return result, [
        audit
        for audit in audits
        if audit.prompt_sha256 in retained_prompt_hashes
    ]


def _successful_artifact() -> RealModelExperimentArtifact:
    manifest, full, masked, no_model, upper = _reports_and_upper()
    plan = _plan()
    assert plan.benchmark_manifest_id == manifest.id
    full_invocations, _ = _invocations(
        plan, AblationConditionKind.FULL_CONTEXT_MODEL
    )
    masked_invocations, audits = _invocations(
        plan, AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
    )
    records = [
        RealExperimentConditionRecord.create(
            plan,
            condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
            invocation_records=full_invocations,
            benchmark_evaluation_report=full,
        ),
        RealExperimentConditionRecord.create(
            plan,
            condition_kind=AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
            invocation_records=masked_invocations,
            benchmark_evaluation_report=masked,
            prompt_visibility_audits=audits,
        ),
        RealExperimentConditionRecord.create(
            plan,
            condition_kind=AblationConditionKind.NO_MODEL_BASELINE,
            benchmark_evaluation_report=no_model,
        ),
        RealExperimentConditionRecord.create(
            plan,
            condition_kind=AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND,
            context_objective_upper_bound_result=upper,
        ),
    ]
    ablation_plan, ablation_results = _condition_results()
    assert ablation_plan.id == plan.ablation_plan_id
    comparison = AblationComparisonBuilder.compare(
        ablation_plan, ablation_results
    )
    return RealModelExperimentArtifact.create(
        experiment_plan=plan,
        condition_records=records,
        ablation_comparison_report=comparison,
        metadata={"fixture": True, "offline_contract": True},
    )


def test_provider_descriptor_is_sanitized_and_secret_free() -> None:
    descriptor = _descriptor(base_url="https://user:secret@fixture.invalid/v1")
    values = descriptor.model_dump(mode="json")
    serialized = json.dumps(values).lower()

    assert set(values) == {
        "id",
        "provider_protocol",
        "model",
        "api_style",
        "strict_json_schema",
        "reasoning_effort",
        "max_completion_tokens",
        "schema_name",
    }
    assert "base_url" not in serialized
    assert "api_key" not in serialized
    assert "secret@" not in serialized


@pytest.mark.parametrize(
    "changes",
    [
        {"model": "fixture-model-v2"},
        {"api_style": LLMAPIStyle.RESPONSES},
        {"json_mode": False},
        {"reasoning_effort": "high"},
        {"max_completion_tokens": 1024},
    ],
)
def test_provider_descriptor_semantic_changes_change_identity(changes) -> None:
    assert _descriptor().id != _descriptor(**changes).id


@pytest.mark.parametrize(
    "changes",
    [
        {"base_url": "https://another-fixture.invalid/v1"},
        {"timeout": 99.0},
    ],
)
def test_provider_execution_mechanics_do_not_change_descriptor(changes) -> None:
    assert _descriptor().id == _descriptor(**changes).id


def test_provider_descriptor_schema_name_changes_identity() -> None:
    config = _config()
    first = RealModelProviderDescriptor.from_provider_config(
        config, schema_name="phase10a_model_authored_chain_claim_v3"
    )
    second = RealModelProviderDescriptor.from_provider_config(
        config, schema_name="fixture-incompatible-schema"
    )

    assert first.id != second.id


def test_plan_binds_exact_four_conditions_one_repetition_and_cases() -> None:
    plan = _plan()
    manifest = _fixture_manifest()

    assert {item.condition_kind for item in plan.condition_specs} == set(
        AblationConditionKind
    )
    assert all(item.repetitions == 1 for item in plan.condition_specs)
    assert plan.case_ids == sorted(item.id for item in manifest.cases)
    assert plan.provider_role_order == list(PHASE10D_PROVIDER_ROLE_ORDER)
    assert plan.execution_mode is ExperimentExecutionMode.OFFLINE_CONTRACT
    assert not hasattr(plan.condition_specs[0], "provider_descriptor")


def test_phase10d_role_order_matches_frozen_agent_workflow() -> None:
    assert PHASE10D_PROVIDER_ROLE_ORDER == tuple(
        agent_class.role for agent_class in AgentWorkflow.agent_classes
    )

    values = _plan().model_dump(mode="json")
    values["provider_role_order"].reverse()
    with pytest.raises(ValidationError, match="fixed provider role order"):
        RealModelExperimentPlan.model_validate(values)


def test_plan_requires_ablation_plan_for_same_frozen_manifest() -> None:
    manifest = _fixture_manifest()
    other_manifest = _manifest([manifest.cases[0]])
    ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=other_manifest.id,
        benchmark_version=other_manifest.benchmark_version,
    )

    with pytest.raises(ValueError, match="frozen manifest"):
        RealModelExperimentPlan.create(
            manifest=manifest,
            ablation_plan=ablation,
            provider_descriptor=_descriptor(),
            execution_mode=ExperimentExecutionMode.OFFLINE_CONTRACT,
        )


def test_plan_rejects_descriptor_with_noncurrent_reasoning_schema() -> None:
    manifest = _fixture_manifest()
    ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    descriptor = RealModelProviderDescriptor.from_provider_config(
        _config(), schema_name="fixture-incompatible-schema"
    )

    with pytest.raises(ValidationError, match="current reasoning schema"):
        RealModelExperimentPlan.create(
            manifest=manifest,
            ablation_plan=ablation,
            provider_descriptor=descriptor,
            execution_mode=ExperimentExecutionMode.OFFLINE_CONTRACT,
        )


def test_plan_order_and_metadata_are_identity_neutral() -> None:
    first = _plan()
    second = _plan(metadata={"fixture_note": "neutral"})
    values = first.model_dump(mode="json")
    values["case_ids"].reverse()
    values["condition_specs"].reverse()
    restored = RealModelExperimentPlan.model_validate(values)

    assert first.id == second.id == restored.id
    assert restored.case_ids == first.case_ids
    assert restored.condition_specs == first.condition_specs


def test_plan_tampered_case_set_fails_identity_validation() -> None:
    values = _plan().model_dump(mode="json")
    values["case_ids"] = [values["case_ids"][0]]

    with pytest.raises(ValidationError, match="not deterministic"):
        RealModelExperimentPlan.model_validate(values)


def test_invocation_key_is_deterministic_and_case_bound() -> None:
    plan = _plan()
    first = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.ATTACK_CHAIN,
    )
    second = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.ATTACK_CHAIN,
    )

    assert first == second
    assert first.repetition_index == 0
    with pytest.raises(ValueError, match="not in frozen"):
        ExperimentCaseInvocationKey.create(
            plan,
            condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
            benchmark_case_id="fixture-extra-case",
            role=ReasoningAgentType.ATTACK_CHAIN,
        )


@pytest.mark.parametrize(
    "condition",
    [
        AblationConditionKind.FULL_CONTEXT_MODEL,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
    ],
)
def test_one_case_has_exactly_four_expected_role_keys(condition) -> None:
    plan = _one_case_plan()
    keys = expected_experiment_invocation_keys(
        plan, condition_kind=condition
    )

    assert len(keys) == 4
    assert [item.role for item in keys] == list(PHASE10D_PROVIDER_ROLE_ORDER)
    assert all(item.repetition_index == 0 for item in keys)


def test_two_cases_have_eight_distinct_keys_per_model_condition() -> None:
    plan = _plan()

    for condition in (
        AblationConditionKind.FULL_CONTEXT_MODEL,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
    ):
        keys = expected_experiment_invocation_keys(
            plan, condition_kind=condition
        )
        assert len(keys) == 8
        assert len({item.id for item in keys}) == 8


def test_role_changes_invocation_identity_and_unsupported_roles_fail_closed() -> None:
    plan = _one_case_plan()
    keys = expected_experiment_invocation_keys(
        plan, condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL
    )

    assert len({item.id for item in keys}) == 4
    for unsupported in (
        ReasoningAgentType.HYPOTHESIS_GENERATOR,
        ReasoningAgentType.EVIDENCE_ANALYST,
        ReasoningAgentType.SECURITY_REASONER,
        ReasoningAgentType.CRITIC,
    ):
        with pytest.raises(ValidationError, match="unsupported Phase 10D"):
            ExperimentCaseInvocationKey.create(
                plan,
                condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
                benchmark_case_id=plan.case_ids[0],
                role=unsupported,
            )


def test_non_provider_conditions_have_no_expected_role_keys() -> None:
    plan = _plan()

    assert expected_experiment_invocation_keys(
        plan, condition_kind=AblationConditionKind.NO_MODEL_BASELINE
    ) == []
    assert expected_experiment_invocation_keys(
        plan,
        condition_kind=AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND,
    ) == []


@pytest.mark.parametrize(
    "condition",
    [
        AblationConditionKind.NO_MODEL_BASELINE,
        AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND,
    ],
)
def test_non_provider_conditions_cannot_have_invocation_key(condition) -> None:
    plan = _plan()
    with pytest.raises(ValidationError, match="only FULL/MASKED"):
        ExperimentCaseInvocationKey.create(
            plan,
            condition_kind=condition,
            benchmark_case_id=plan.case_ids[0],
            role=ReasoningAgentType.ATTACK_CHAIN,
        )


def test_completed_invocation_retains_only_exact_hashes() -> None:
    plan = _plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.ATTACK_CHAIN,
    )
    prompt = _prompt(plan.case_ids[0], ReasoningPromptVisibility.FULL_CONTEXT)
    response = '{"fixture":"response"}'
    record = ModelInvocationRecord.completed(
        plan, key, prompt=prompt, raw_provider_response=response
    )
    serialized = record.model_dump(mode="json")

    assert record.prompt_sha256 == structured_prompt_request_sha256(prompt)
    assert record.provider_response_sha256 == provider_response_sha256(response)
    assert record.disposition is ModelInvocationDisposition.COMPLETED
    assert "system_prompt" not in json.dumps(serialized)
    assert "user_prompt" not in json.dumps(serialized)
    assert response not in json.dumps(serialized)


def test_invocation_prompt_role_must_match_role_key() -> None:
    plan = _one_case_plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.CODE,
    )
    wrong_role_prompt = _prompt(
        plan.case_ids[0],
        ReasoningPromptVisibility.FULL_CONTEXT,
        ReasoningAgentType.HARDWARE,
    )

    with pytest.raises(ValueError, match="prompt role and key role mismatch"):
        ModelInvocationRecord.completed(
            plan,
            key,
            prompt=wrong_role_prompt,
            raw_provider_response="{}",
        )


def test_full_and_masked_final_prompt_hashes_are_distinct() -> None:
    case_id = _plan().case_ids[0]
    full = _prompt(case_id, ReasoningPromptVisibility.FULL_CONTEXT)
    masked = _prompt(case_id, ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT)

    assert structured_prompt_request_sha256(full) != (
        structured_prompt_request_sha256(masked)
    )


def test_wrong_plan_or_provider_descriptor_fails_invocation() -> None:
    first = _plan()
    second = _plan(descriptor=_descriptor(model="fixture-other-model"))
    key = ExperimentCaseInvocationKey.create(
        first,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=first.case_ids[0],
        role=ReasoningAgentType.ATTACK_CHAIN,
    )
    prompt = _prompt(first.case_ids[0], ReasoningPromptVisibility.FULL_CONTEXT)

    with pytest.raises(ValueError, match="another experiment plan"):
        ModelInvocationRecord.completed(
            second, key, prompt=prompt, raw_provider_response="{}"
        )
    with pytest.raises(ValueError, match="provider descriptor mismatch"):
        ModelInvocationRecord.completed(
            first,
            key,
            prompt=prompt,
            raw_provider_response="{}",
            provider_descriptor_id="real-model-provider-descriptor:wrong",
        )


def test_failed_invocation_requires_bounded_failure_and_occupies_slot() -> None:
    plan = _plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.ATTACK_CHAIN,
    )
    failure = RealModelInvocationFailure.create(
        key,
        stage=RealModelInvocationFailureStage.PROVIDER_TRANSPORT,
        failure_code=RealModelInvocationFailureCode.PROVIDER_TIMEOUT,
    )
    prompt = _prompt(plan.case_ids[0], ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT)
    record = ModelInvocationRecord.failed(
        plan, key, failure=failure, prompt=prompt
    )

    assert record.disposition is ModelInvocationDisposition.FAILED
    assert record.failure == failure
    assert record.prompt_sha256 == structured_prompt_request_sha256(prompt)
    assert record.provider_response_sha256 is None


def test_failed_invocation_retains_hashes_available_at_failure_stage() -> None:
    plan = _one_case_plan()
    case_id = plan.case_ids[0]
    prompt = _prompt(
        case_id,
        ReasoningPromptVisibility.FULL_CONTEXT,
        ReasoningAgentType.CODE,
    )
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=case_id,
        role=ReasoningAgentType.CODE,
    )
    parse_failure = RealModelInvocationFailure.create(
        key,
        stage=RealModelInvocationFailureStage.STRUCTURED_PARSE,
        failure_code=RealModelInvocationFailureCode.PROVIDER_CONTRACT_REJECTED,
    )
    response = '{"fixture":"invalid"}'
    record = ModelInvocationRecord.failed(
        plan,
        key,
        failure=parse_failure,
        prompt=prompt,
        raw_provider_response=response,
    )

    assert record.prompt_sha256 == structured_prompt_request_sha256(prompt)
    assert record.provider_response_sha256 == provider_response_sha256(response)

    with pytest.raises(ValidationError, match="post-response failure"):
        ModelInvocationRecord.failed(
            plan,
            key,
            failure=parse_failure,
            prompt=prompt,
        )


def test_prompt_construction_failure_may_have_no_hashes() -> None:
    plan = _one_case_plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.CODE,
    )
    failure = RealModelInvocationFailure.create(
        key,
        stage=RealModelInvocationFailureStage.PROMPT_CONSTRUCTION,
        failure_code=RealModelInvocationFailureCode.OTHER_BOUNDED_FAILURE,
    )
    record = ModelInvocationRecord.failed(plan, key, failure=failure)

    assert record.prompt_sha256 is None
    assert record.provider_response_sha256 is None


def test_not_attempted_is_hashless_failureless_and_role_bound() -> None:
    plan = _one_case_plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.VULNERABILITY,
    )
    record = ModelInvocationRecord.not_attempted(
        plan,
        key,
        blocked_by_role=ReasoningAgentType.HARDWARE,
    )

    assert record.disposition is ModelInvocationDisposition.NOT_ATTEMPTED
    assert record.prompt_sha256 is None
    assert record.provider_response_sha256 is None
    assert record.failure is None
    assert record.blocked_by_role is ReasoningAgentType.HARDWARE


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"prompt_sha256": "0" * 64}, "only a blocking role"),
        ({"provider_response_sha256": "1" * 64}, "only a blocking role"),
        ({"blocked_by_role": None}, "only a blocking role"),
    ],
)
def test_not_attempted_rejects_hashes_or_missing_blocker(
    mutation, message
) -> None:
    plan = _one_case_plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.ATTACK_CHAIN,
    )
    values = ModelInvocationRecord.not_attempted(
        plan,
        key,
        blocked_by_role=ReasoningAgentType.CODE,
    ).model_dump(mode="json")
    values.update(mutation)

    with pytest.raises(ValidationError, match=message):
        ModelInvocationRecord.model_validate(values)


def test_not_attempted_rejects_failure_object() -> None:
    plan = _one_case_plan()
    failed_key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.CODE,
    )
    blocked_key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.HARDWARE,
    )
    failure = RealModelInvocationFailure.create(
        failed_key,
        stage=RealModelInvocationFailureStage.PROVIDER_TRANSPORT,
        failure_code=RealModelInvocationFailureCode.PROVIDER_TIMEOUT,
    )
    values = ModelInvocationRecord.not_attempted(
        plan,
        blocked_key,
        blocked_by_role=ReasoningAgentType.CODE,
    ).model_dump(mode="json")
    values["failure"] = failure.model_dump(mode="json")

    with pytest.raises(ValidationError, match="only a blocking role"):
        ModelInvocationRecord.model_validate(values)


@pytest.mark.parametrize(
    "mutation",
    [
        {"disposition": "completed"},
        {"failure": None},
    ],
)
def test_failed_invocation_cannot_masquerade_or_drop_failure(mutation) -> None:
    plan = _plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.ATTACK_CHAIN,
    )
    failure = RealModelInvocationFailure.create(
        key,
        stage=RealModelInvocationFailureStage.PROVIDER_CONNECTION,
        failure_code=RealModelInvocationFailureCode.PROVIDER_UNAVAILABLE,
    )
    values = ModelInvocationRecord.failed(
        plan,
        key,
        failure=failure,
        prompt=_prompt(
            plan.case_ids[0],
            ReasoningPromptVisibility.FULL_CONTEXT,
            ReasoningAgentType.ATTACK_CHAIN,
        ),
    ).model_dump(mode="json")
    values.update(mutation)

    with pytest.raises(ValidationError):
        ModelInvocationRecord.model_validate(values)


def test_completed_invocation_requires_both_hashes_and_no_failure() -> None:
    plan = _plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.ATTACK_CHAIN,
    )
    prompt = _prompt(plan.case_ids[0], ReasoningPromptVisibility.FULL_CONTEXT)
    values = ModelInvocationRecord.completed(
        plan, key, prompt=prompt, raw_provider_response="{}"
    ).model_dump(mode="json")
    values["provider_response_sha256"] = None

    with pytest.raises(ValidationError, match="requires both hashes"):
        ModelInvocationRecord.model_validate(values)


def test_prompt_and_response_hashes_are_exact_deterministic_and_roundtrip() -> None:
    prompt = _prompt("fixture-hash-case", ReasoningPromptVisibility.FULL_CONTEXT)
    first_prompt_hash = structured_prompt_request_sha256(prompt)
    assert first_prompt_hash == structured_prompt_request_sha256(prompt)
    assert provider_response_sha256("fixture") == provider_response_sha256(
        "fixture"
    )
    assert provider_response_sha256("fixture") != provider_response_sha256(
        "fixturf"
    )
    artifact = _successful_artifact()
    restored = RealModelExperimentArtifact.model_validate_json(
        artifact.model_dump_json()
    )
    assert restored == artifact
    for condition in restored.condition_records:
        if condition.condition_kind in {
            AblationConditionKind.FULL_CONTEXT_MODEL,
            AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        }:
            assert {
                item.invocation_key.role for item in condition.invocation_records
            } == set(PHASE10D_PROVIDER_ROLE_ORDER)


def test_failed_invocation_rejects_supplied_prompt_with_wrong_schema() -> None:
    plan = _plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.ATTACK_CHAIN,
    )
    failure = RealModelInvocationFailure.create(
        key,
        stage=RealModelInvocationFailureStage.PROVIDER_TRANSPORT,
        failure_code=RealModelInvocationFailureCode.PROVIDER_UNAVAILABLE,
    )
    prompt = _prompt(plan.case_ids[0], ReasoningPromptVisibility.FULL_CONTEXT)
    wrong_schema_prompt = prompt.model_copy(
        update={"schema_name": "fixture-wrong-schema"}
    )

    with pytest.raises(ValueError, match="schema and descriptor mismatch"):
        ModelInvocationRecord.failed(
            plan,
            key,
            failure=failure,
            prompt=wrong_schema_prompt,
        )


def test_model_condition_requires_exact_case_accounting() -> None:
    _, full, _, _, _ = _reports_and_upper()
    plan = _plan()
    invocations, _ = _invocations(
        plan, AblationConditionKind.FULL_CONTEXT_MODEL
    )

    with pytest.raises(ValueError, match="every planned case role"):
        RealExperimentConditionRecord.create(
            plan,
            condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
            invocation_records=invocations[:-1],
            benchmark_evaluation_report=full,
        )


def test_model_condition_rejects_duplicate_or_missing_role_record() -> None:
    _, full, _, _, _ = _reports_and_upper()
    plan = _plan()
    records, _ = _invocations(
        plan, AblationConditionKind.FULL_CONTEXT_MODEL
    )

    with pytest.raises(ValueError, match="every planned case role"):
        RealExperimentConditionRecord.create(
            plan,
            condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
            invocation_records=records[:-1],
            benchmark_evaluation_report=full,
        )
    with pytest.raises(ValueError, match="every planned case role"):
        RealExperimentConditionRecord.create(
            plan,
            condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
            invocation_records=[*records[:-1], records[0]],
            benchmark_evaluation_report=full,
        )


def test_all_four_completed_per_case_is_valid_and_semantic_miss_is_not_failure() -> None:
    _, _, masked_report, _, _ = _reports_and_upper()
    plan = _plan()
    records, audits = _invocations(
        plan, AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
    )
    condition = RealExperimentConditionRecord.create(
        plan,
        condition_kind=AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        invocation_records=records,
        benchmark_evaluation_report=masked_report,
        prompt_visibility_audits=audits,
    )

    assert all(
        item.disposition is ModelInvocationDisposition.COMPLETED
        for item in condition.invocation_records
    )
    assert masked_report.claim_binding_status_counts["mismatched"] == 1


@pytest.mark.parametrize(
    ("failed_role", "not_attempted_count"),
    [
        (ReasoningAgentType.CODE, 3),
        (ReasoningAgentType.HARDWARE, 2),
        (ReasoningAgentType.ATTACK_CHAIN, 0),
    ],
)
def test_valid_sequential_fail_stop_shapes(
    failed_role, not_attempted_count
) -> None:
    plan = _plan()
    records, _ = _fail_stop_invocations(
        plan,
        AblationConditionKind.FULL_CONTEXT_MODEL,
        failed_case_id=plan.case_ids[0],
        failed_role=failed_role,
    )
    condition = RealExperimentConditionRecord.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        invocation_records=list(reversed(records)),
    )
    failed_case_records = [
        item
        for item in condition.invocation_records
        if item.invocation_key.benchmark_case_id == plan.case_ids[0]
    ]

    assert sum(
        item.disposition is ModelInvocationDisposition.FAILED
        for item in failed_case_records
    ) == 1
    assert sum(
        item.disposition is ModelInvocationDisposition.NOT_ATTEMPTED
        for item in failed_case_records
    ) == not_attempted_count


def test_two_failed_roles_in_one_case_fail_closed() -> None:
    plan = _plan()
    records, _ = _fail_stop_invocations(
        plan,
        AblationConditionKind.FULL_CONTEXT_MODEL,
        failed_case_id=plan.case_ids[0],
        failed_role=ReasoningAgentType.CODE,
    )
    hardware_index = next(
        index
        for index, item in enumerate(records)
        if item.invocation_key.benchmark_case_id == plan.case_ids[0]
        and item.invocation_key.role is ReasoningAgentType.HARDWARE
    )
    key = records[hardware_index].invocation_key
    failure = RealModelInvocationFailure.create(
        key,
        stage=RealModelInvocationFailureStage.PROVIDER_TRANSPORT,
        failure_code=RealModelInvocationFailureCode.PROVIDER_TIMEOUT,
    )
    records[hardware_index] = ModelInvocationRecord.failed(
        plan,
        key,
        failure=failure,
        prompt=_prompt(
            plan.case_ids[0],
            ReasoningPromptVisibility.FULL_CONTEXT,
            ReasoningAgentType.HARDWARE,
        ),
    )

    with pytest.raises(ValidationError, match="at most one failed role"):
        RealExperimentConditionRecord.create(
            plan,
            condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
            invocation_records=records,
        )


def test_not_attempted_followed_by_completed_fails_closed() -> None:
    plan = _plan()
    records, _ = _fail_stop_invocations(
        plan,
        AblationConditionKind.FULL_CONTEXT_MODEL,
        failed_case_id=plan.case_ids[0],
        failed_role=ReasoningAgentType.CODE,
    )
    original, _ = _invocations(
        plan, AblationConditionKind.FULL_CONTEXT_MODEL
    )
    attack_chain_completed = next(
        item
        for item in original
        if item.invocation_key.benchmark_case_id == plan.case_ids[0]
        and item.invocation_key.role is ReasoningAgentType.ATTACK_CHAIN
    )
    records = [
        attack_chain_completed
        if item.invocation_key.id == attack_chain_completed.invocation_key.id
        else item
        for item in records
    ]

    with pytest.raises(ValidationError, match="fail-stop disposition shape"):
        RealExperimentConditionRecord.create(
            plan,
            condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
            invocation_records=records,
        )


def test_failure_in_one_case_does_not_block_another_case() -> None:
    plan = _plan()
    records, _ = _fail_stop_invocations(
        plan,
        AblationConditionKind.FULL_CONTEXT_MODEL,
        failed_case_id=plan.case_ids[0],
        failed_role=ReasoningAgentType.HARDWARE,
    )
    condition = RealExperimentConditionRecord.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        invocation_records=records,
    )
    other_case = [
        item
        for item in condition.invocation_records
        if item.invocation_key.benchmark_case_id == plan.case_ids[1]
    ]

    assert len(other_case) == 4
    assert all(
        item.disposition is ModelInvocationDisposition.COMPLETED
        for item in other_case
    )


def test_persisted_condition_rejects_invocation_from_another_plan() -> None:
    _, full, _, _, _ = _reports_and_upper()
    plan = _plan()
    other_plan = _plan(descriptor=_descriptor(model="fixture-other-model"))
    invocations, _ = _invocations(
        plan, AblationConditionKind.FULL_CONTEXT_MODEL
    )
    other_invocations, _ = _invocations(
        other_plan, AblationConditionKind.FULL_CONTEXT_MODEL
    )
    condition = RealExperimentConditionRecord.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        invocation_records=invocations,
        benchmark_evaluation_report=full,
    )
    values = condition.model_dump(mode="json")
    values["invocation_records"][0] = other_invocations[0].model_dump(mode="json")
    values["id"] = real_experiment_condition_record_id(
        experiment_plan_id=values["experiment_plan_id"],
        condition_kind=values["condition_kind"],
        benchmark_manifest_id=values["benchmark_manifest_id"],
        invocation_record_ids=[
            item["id"] for item in values["invocation_records"]
        ],
        benchmark_evaluation_report_id=values[
            "benchmark_evaluation_report"
        ]["id"],
        context_objective_upper_bound_result_id=None,
        prompt_visibility_audit_ids=[],
        condition_failure_id=None,
    )

    with pytest.raises(ValidationError, match="experiment plan mismatch"):
        RealExperimentConditionRecord.model_validate(values)
    with pytest.raises(ValueError, match="every planned case"):
        RealExperimentConditionRecord.create(
            plan,
            condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
            invocation_records=[invocations[0], invocations[0]],
            benchmark_evaluation_report=full,
        )


@pytest.mark.parametrize(
    "condition",
    [
        AblationConditionKind.NO_MODEL_BASELINE,
        AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND,
    ],
)
def test_non_provider_condition_rejects_model_invocation(condition) -> None:
    plan = _plan()
    invocations, _ = _invocations(
        plan, AblationConditionKind.FULL_CONTEXT_MODEL
    )

    with pytest.raises(ValueError, match="non-provider"):
        RealExperimentConditionRecord.create(
            plan,
            condition_kind=condition,
            invocation_records=invocations,
        )


def test_no_model_and_upper_bound_have_zero_provider_role_records() -> None:
    artifact = _successful_artifact()
    by_kind = {
        item.condition_kind: item for item in artifact.condition_records
    }

    assert by_kind[
        AblationConditionKind.NO_MODEL_BASELINE
    ].invocation_records == []
    assert by_kind[
        AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND
    ].invocation_records == []


def test_semantic_missing_claim_is_not_invocation_failure() -> None:
    _, _, _, no_model, _ = _reports_and_upper()
    plan = _plan()
    record = RealExperimentConditionRecord.create(
        plan,
        condition_kind=AblationConditionKind.NO_MODEL_BASELINE,
        benchmark_evaluation_report=no_model,
    )

    assert record.condition_failure is None
    assert record.invocation_records == []
    assert no_model.claim_binding_status_counts["missing"] > 0


def test_successful_offline_artifact_has_derived_quality_but_is_not_real() -> None:
    artifact = _successful_artifact()

    assert artifact.provider_configuration_comparable is True
    assert artifact.benchmark_comparable is True
    assert artifact.prompt_visibility_valid is True
    assert artifact.execution_complete is True
    assert artifact.experiment_plan.execution_mode is ExperimentExecutionMode.OFFLINE_CONTRACT
    assert artifact.is_real_provider_result is False
    assert {item.condition_kind for item in artifact.condition_records} == set(
        AblationConditionKind
    )
    masked = next(
        item
        for item in artifact.condition_records
        if item.condition_kind
        is AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
    )
    assert len(masked.prompt_visibility_audits) == 4 * len(
        artifact.experiment_plan.case_ids
    )
    assert all(
        item.status is PromptVisibilityAuditStatus.PASS
        for item in masked.prompt_visibility_audits
    )


def test_masked_attempted_prompt_requires_exact_invocation_bound_audit() -> None:
    plan = _plan()
    records, audits = _fail_stop_invocations(
        plan,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        failed_case_id=plan.case_ids[0],
        failed_role=ReasoningAgentType.HARDWARE,
    )

    with pytest.raises(ValidationError, match="one audit per attempted"):
        RealExperimentConditionRecord.create(
            plan,
            condition_kind=AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
            invocation_records=records,
            prompt_visibility_audits=audits[:-1],
        )

    unrelated_prompt = _prompt(
        "fixture-unrelated-case",
        ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
        ReasoningAgentType.CODE,
    )
    unrelated_audit = PromptVisibilityAuditor.audit(
        unrelated_prompt,
        hidden_reference_ids=["fixture-unrelated-hidden-reference"],
    )
    with pytest.raises(ValidationError, match="one audit per attempted"):
        RealExperimentConditionRecord.create(
            plan,
            condition_kind=AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
            invocation_records=records,
            prompt_visibility_audits=[*audits[:-1], unrelated_audit],
        )


def test_masked_not_attempted_roles_require_no_prompt_audit() -> None:
    plan = _plan()
    records, audits = _fail_stop_invocations(
        plan,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        failed_case_id=plan.case_ids[0],
        failed_role=ReasoningAgentType.HARDWARE,
    )
    condition = RealExperimentConditionRecord.create(
        plan,
        condition_kind=AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        invocation_records=records,
        prompt_visibility_audits=audits,
    )

    assert len(condition.prompt_visibility_audits) == sum(
        item.prompt_sha256 is not None for item in condition.invocation_records
    )
    assert all(
        item.prompt_sha256 is None
        for item in condition.invocation_records
        if item.disposition is ModelInvocationDisposition.NOT_ATTEMPTED
    )


def test_full_condition_never_requires_masked_prompt_audits() -> None:
    _, full, _, _, _ = _reports_and_upper()
    plan = _plan()
    records, _ = _invocations(
        plan, AblationConditionKind.FULL_CONTEXT_MODEL
    )

    condition = RealExperimentConditionRecord.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        invocation_records=records,
        benchmark_evaluation_report=full,
    )
    assert condition.prompt_visibility_audits == []


def test_leaked_masked_audit_is_explicitly_invalid_without_metric_mutation() -> None:
    artifact = _successful_artifact()
    values = artifact.model_dump(mode="json")
    masked = next(
        item
        for item in values["condition_records"]
        if item["condition_kind"] == "masked_chain_context_model"
    )
    audit = masked["prompt_visibility_audits"][0]
    audit["leaked_reference_ids"] = [audit["hidden_reference_ids"][0]]
    audit["status"] = PromptVisibilityAuditStatus.LEAK_DETECTED.value
    from chipchain.evaluation.ablation_models import prompt_visibility_audit_id

    audit["id"] = prompt_visibility_audit_id(
        prompt_sha256=audit["prompt_sha256"],
        hidden_reference_ids=audit["hidden_reference_ids"],
        leaked_reference_ids=audit["leaked_reference_ids"],
        status=PromptVisibilityAuditStatus.LEAK_DETECTED,
    )
    original_masked = next(
        item
        for item in artifact.condition_records
        if item.condition_kind
        is AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
    )
    leaked_audit = type(original_masked.prompt_visibility_audits[0]).model_validate(
        audit
    )
    audits = [
        leaked_audit if item.prompt_sha256 == leaked_audit.prompt_sha256 else item
        for item in original_masked.prompt_visibility_audits
    ]
    condition = RealExperimentConditionRecord.create(
        artifact.experiment_plan,
        condition_kind=AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        invocation_records=original_masked.invocation_records,
        benchmark_evaluation_report=original_masked.benchmark_evaluation_report,
        prompt_visibility_audits=audits,
    )
    records = [
        condition if item.condition_kind is condition.condition_kind else item
        for item in artifact.condition_records
    ]
    invalid = RealModelExperimentArtifact.create(
        experiment_plan=artifact.experiment_plan,
        condition_records=records,
        ablation_comparison_report=artifact.ablation_comparison_report,
    )

    assert invalid.prompt_visibility_valid is False
    assert invalid.ablation_comparison_report == artifact.ablation_comparison_report


def test_explicit_condition_failure_remains_accounted() -> None:
    artifact = _successful_artifact()
    plan = artifact.experiment_plan
    failure = AblationConditionExecutionFailure.create(
        ablation_plan_id=plan.ablation_plan_id,
        condition_kind=AblationConditionKind.NO_MODEL_BASELINE,
        stage=AblationConditionFailureStage.REPORT_ASSEMBLY,
        failure_code=AblationConditionFailureCode.REPORT_ASSEMBLY_FAILED,
    )
    failed_condition = RealExperimentConditionRecord.create(
        plan,
        condition_kind=AblationConditionKind.NO_MODEL_BASELINE,
        condition_failure=failure,
    )
    records = [
        failed_condition
        if item.condition_kind is AblationConditionKind.NO_MODEL_BASELINE
        else item
        for item in artifact.condition_records
    ]
    incomplete = RealModelExperimentArtifact.create(
        experiment_plan=plan,
        condition_records=records,
    )

    assert incomplete.execution_complete is False
    assert next(
        item
        for item in incomplete.condition_records
        if item.condition_kind is AblationConditionKind.NO_MODEL_BASELINE
    ).condition_failure == failure


def test_completed_provider_slots_without_report_require_downstream_failure() -> None:
    artifact = _successful_artifact()
    plan = artifact.experiment_plan
    full = next(
        item
        for item in artifact.condition_records
        if item.condition_kind is AblationConditionKind.FULL_CONTEXT_MODEL
    )
    failure = AblationConditionExecutionFailure.create(
        ablation_plan_id=plan.ablation_plan_id,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        stage=AblationConditionFailureStage.REPORT_ASSEMBLY,
        failure_code=AblationConditionFailureCode.REPORT_ASSEMBLY_FAILED,
    )
    failed_condition = RealExperimentConditionRecord.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        invocation_records=full.invocation_records,
        condition_failure=failure,
    )
    incomplete = RealModelExperimentArtifact.create(
        experiment_plan=plan,
        condition_records=[
            failed_condition
            if item.condition_kind is AblationConditionKind.FULL_CONTEXT_MODEL
            else item
            for item in artifact.condition_records
        ],
    )

    assert all(
        item.disposition is ModelInvocationDisposition.COMPLETED
        for item in failed_condition.invocation_records
    )
    assert failed_condition.benchmark_evaluation_report is None
    assert incomplete.execution_complete is False

    with pytest.raises(ValidationError, match="report xor downstream failure"):
        RealExperimentConditionRecord.create(
            plan,
            condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
            invocation_records=full.invocation_records,
        )


def test_condition_failure_and_failed_invocation_cannot_disappear() -> None:
    artifact = _successful_artifact()
    plan = artifact.experiment_plan
    masked = next(
        item
        for item in artifact.condition_records
        if item.condition_kind
        is AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
    )
    failed_records, audits = _fail_stop_invocations(
        plan,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        failed_case_id=plan.case_ids[0],
        failed_role=ReasoningAgentType.CODE,
        failure_stage=RealModelInvocationFailureStage.STRUCTURED_PARSE,
        response_available=True,
    )
    failed_condition = RealExperimentConditionRecord.create(
        plan,
        condition_kind=AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        invocation_records=failed_records,
        prompt_visibility_audits=audits,
    )
    records = [
        failed_condition
        if item.condition_kind is AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
        else item
        for item in artifact.condition_records
    ]
    incomplete = RealModelExperimentArtifact.create(
        experiment_plan=plan,
        condition_records=records,
    )

    assert incomplete.execution_complete is False
    assert any(
        item.disposition is ModelInvocationDisposition.FAILED
        for item in failed_condition.invocation_records
    )
    assert sum(
        item.disposition is ModelInvocationDisposition.NOT_ATTEMPTED
        for item in failed_condition.invocation_records
    ) == 3


def test_artifact_requires_comparison_for_same_ablation_and_manifest_when_present() -> None:
    artifact = _successful_artifact()
    other_manifest = _manifest([_fixture_manifest().cases[0]])
    other_plan = AblationExperimentPlan.create(
        benchmark_manifest_id=other_manifest.id,
        benchmark_version=other_manifest.benchmark_version,
    )
    _, results = _condition_results()
    values = results[0].model_dump(mode="json")
    values["ablation_plan_id"] = other_plan.id
    values["benchmark_manifest_id"] = other_manifest.id

    with pytest.raises(ValueError):
        RealModelExperimentArtifact.create(
            experiment_plan=artifact.experiment_plan,
            condition_records=artifact.condition_records,
            ablation_comparison_report=artifact.ablation_comparison_report.model_copy(
                update={"benchmark_manifest_id": other_manifest.id}
            ),
        )


def test_artifact_order_and_metadata_are_identity_neutral_and_tamper_fails() -> None:
    artifact = _successful_artifact()
    reordered = RealModelExperimentArtifact.create(
        experiment_plan=artifact.experiment_plan,
        condition_records=list(reversed(artifact.condition_records)),
        ablation_comparison_report=artifact.ablation_comparison_report,
        metadata={"fixture_note": "neutral"},
    )
    assert reordered.id == artifact.id
    values = artifact.model_dump(mode="json")
    values["id"] = "real-model-experiment-artifact:tampered"
    with pytest.raises(ValidationError, match="not deterministic"):
        RealModelExperimentArtifact.model_validate(values)


@pytest.mark.parametrize(
    "metadata",
    [
        {"api_key": "fixture-secret"},
        {"note": "Authorization: Bearer fixture-secret"},
        {"stderr": "raw provider stderr"},
        {"note": "Traceback (most recent call last)"},
        {"note": "/home/fixture/private.txt"},
        {"note": "C:\\fixture\\private.txt"},
        {"note": "file:///tmp/private.txt"},
        {"base_url": "https://fixture-provider.invalid/v1"},
        {"endpoint": "https://fixture-provider.invalid/responses"},
        {"proxy": "https://fixture-proxy.invalid"},
        {"raw_prompt": "fixture raw model prompt"},
        {"raw_response": "fixture raw provider response"},
        {"exception_repr": "FixtureProviderError('details')"},
    ],
)
def test_failure_and_artifact_metadata_reject_secrets_diagnostics_paths(metadata) -> None:
    plan = _plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.ATTACK_CHAIN,
    )
    with pytest.raises(ValidationError):
        RealModelInvocationFailure.create(
            key,
            stage=RealModelInvocationFailureStage.PROVIDER_TRANSPORT,
            failure_code=RealModelInvocationFailureCode.OTHER_BOUNDED_FAILURE,
            metadata=metadata,
        )
    artifact = _successful_artifact()
    with pytest.raises(ValidationError):
        RealModelExperimentArtifact.create(
            experiment_plan=artifact.experiment_plan,
            condition_records=artifact.condition_records,
            metadata=metadata,
        )


def test_artifact_rejects_forbidden_metadata_nested_in_prompt_audit() -> None:
    artifact = _successful_artifact()
    masked = next(
        item
        for item in artifact.condition_records
        if item.condition_kind
        is AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
    )
    poisoned_audit = masked.prompt_visibility_audits[0].model_copy(
        update={"metadata": {"raw_prompt": "fixture raw prompt"}}
    )
    audits = [
        poisoned_audit if item.id == poisoned_audit.id else item
        for item in masked.prompt_visibility_audits
    ]
    poisoned_condition = RealExperimentConditionRecord.create(
        artifact.experiment_plan,
        condition_kind=AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        invocation_records=masked.invocation_records,
        benchmark_evaluation_report=masked.benchmark_evaluation_report,
        prompt_visibility_audits=audits,
    )
    records = [
        poisoned_condition
        if item.condition_kind is AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
        else item
        for item in artifact.condition_records
    ]

    with pytest.raises(ValidationError, match="forbidden transport content"):
        RealModelExperimentArtifact.create(
            experiment_plan=artifact.experiment_plan,
            condition_records=records,
            ablation_comparison_report=artifact.ablation_comparison_report,
        )


def test_ground_truth_never_enters_prompt_or_provider_contracts() -> None:
    builder_parameters = inspect.signature(
        RoleBasedReasoningPromptBuilder.build
    ).parameters
    plan_parameters = inspect.signature(RealModelExperimentPlan.create).parameters
    forbidden = {"ground_truth", "ground_truth_chain", "benchmark_case"}

    assert forbidden.isdisjoint(builder_parameters)
    assert "manifest" in plan_parameters
    serialized = _successful_artifact().model_dump(mode="json")
    assert serialized["experiment_plan"]["execution_mode"] == "offline_contract"


def test_no_threshold_or_real_provider_execution_artifact_is_created() -> None:
    artifact = _successful_artifact()
    serialized = json.dumps(artifact.model_dump(mode="json")).lower()

    assert "threshold_pass" not in serialized
    assert "project_conclusion" not in serialized
    assert artifact.is_real_provider_result is False
