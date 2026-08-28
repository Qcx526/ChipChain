"""Offline Phase 10D Step 1 real-model experiment provenance tests."""

from __future__ import annotations

from copy import deepcopy
import hashlib
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
    AblationConditionResult,
    AblationExperimentPlan,
    BenchmarkCaseLabel,
    BenchmarkCaseRunRecord,
    BenchmarkEvaluationRunner,
    ChainFeasibilityStatus,
    ContextObjectiveUpperBoundEvaluator,
    ExperimentCaseInvocationKey,
    ExperimentExecutionMode,
    ModelInvocationDisposition,
    ModelClaimBindingStatus,
    ModelInvocationRecord,
    PHASE10D_MASKED_PROMPT_PROJECTION_CONTRACT,
    PHASE10D_PROVIDER_ROLE_ORDER,
    PHASE10D_RESPONSES_COMPLETION_CONTRACT,
    PromptVisibilityAuditStatus,
    PromptVisibilityAuditor,
    ProviderResponseFailureDetail,
    RealExperimentConditionRecord,
    RealModelExperimentArtifact,
    RealModelExperimentPlan,
    RealModelInvocationFailure,
    RealModelInvocationFailureCode,
    RealModelInvocationFailureStage,
    RealModelProviderDescriptor,
    StructuredParseFailureDetail,
    expected_experiment_invocation_keys,
    real_experiment_condition_record_id,
    real_model_experiment_plan_id,
    real_model_invocation_failure_id,
    real_model_provider_descriptor_id,
    strict_schema_bundle_sha256,
    structured_prompt_request_sha256,
    provider_response_sha256,
)
from chipchain.reasoning import (
    LLMAPIStyle,
    ReasoningAgentType,
    ReasoningPromptVisibility,
    RoleBasedReasoningPromptBuilder,
    reasoning_provider_output_json_schema_for_role,
)
from chipchain.reasoning.models import LLMProviderConfig
from tests.test_phase10b_benchmark_evaluation import (
    _bundle,
    _case,
    _fixture_manifest,
    _manifest,
    _owned_runs,
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


def _ablation_plan_for_experiment(
    plan: RealModelExperimentPlan,
) -> AblationExperimentPlan:
    ablation_plan = AblationExperimentPlan.create(
        benchmark_manifest_id=plan.benchmark_manifest_id,
        benchmark_version=plan.benchmark_version,
    )
    assert ablation_plan.id == plan.ablation_plan_id
    return ablation_plan


def _phase10c_results_from_execution(
    plan: RealModelExperimentPlan,
    records: list[RealExperimentConditionRecord],
) -> list[AblationConditionResult]:
    results = []
    for record in records:
        results.append(
            AblationConditionResult.create(
                ablation_plan_id=plan.ablation_plan_id,
                condition_kind=record.condition_kind,
                benchmark_manifest_id=plan.benchmark_manifest_id,
                benchmark_evaluation_report=(
                    record.benchmark_evaluation_report
                ),
                context_objective_upper_bound_result=(
                    record.context_objective_upper_bound_result
                ),
                prompt_visibility_audit_ids=[
                    audit.id for audit in record.prompt_visibility_audits
                ],
                execution_failure=record.condition_failure,
            )
        )
    return results


def _comparison_from_execution(
    plan: RealModelExperimentPlan,
    records: list[RealExperimentConditionRecord],
):
    return AblationComparisonBuilder.compare(
        _ablation_plan_for_experiment(plan),
        _phase10c_results_from_execution(plan, records),
    )


def _comparison_with_condition_result(
    artifact: RealModelExperimentArtifact,
    replacement: AblationConditionResult,
):
    results = _phase10c_results_from_execution(
        artifact.experiment_plan, artifact.condition_records
    )
    return AblationComparisonBuilder.compare(
        _ablation_plan_for_experiment(artifact.experiment_plan),
        [
            replacement
            if item.condition_kind is replacement.condition_kind
            else item
            for item in results
        ],
    )


def _alternative_same_benchmark_outputs():
    manifest = _fixture_manifest()
    positive = _case(manifest, BenchmarkCaseLabel.POSITIVE_FEASIBLE)
    negative = _case(manifest, BenchmarkCaseLabel.NEGATIVE_CONTROL)
    alternative_report_runs = [
        BenchmarkCaseRunRecord.from_candidate(
            _bundle(
                positive,
                binding_status=ModelClaimBindingStatus.MISSING,
                feasibility_status=ChainFeasibilityStatus.UNRESOLVED,
            )
        ),
        BenchmarkCaseRunRecord.from_candidate(
            _bundle(
                negative,
                binding_status=ModelClaimBindingStatus.ALIGNED,
            )
        ),
    ]
    alternative_upper_runs = [
        BenchmarkCaseRunRecord.from_candidate(
            _bundle(
                positive,
                feasibility_status=ChainFeasibilityStatus.UNRESOLVED,
            )
        ),
        _owned_runs(manifest)[1],
    ]
    return (
        BenchmarkEvaluationRunner().evaluate(
            manifest, alternative_report_runs
        ),
        ContextObjectiveUpperBoundEvaluator().evaluate(
            manifest, alternative_upper_runs
        ),
    )


def _condition_failure(
    plan: RealModelExperimentPlan,
    condition_kind: AblationConditionKind,
    *,
    alternate: bool = False,
) -> AblationConditionExecutionFailure:
    return AblationConditionExecutionFailure.create(
        ablation_plan_id=plan.ablation_plan_id,
        condition_kind=condition_kind,
        stage=(
            AblationConditionFailureStage.ORCHESTRATION
            if alternate
            else AblationConditionFailureStage.REPORT_ASSEMBLY
        ),
        failure_code=(
            AblationConditionFailureCode.CONDITION_ORCHESTRATION_FAILED
            if alternate
            else AblationConditionFailureCode.REPORT_ASSEMBLY_FAILED
        ),
    )


def _execution_records_with_failure(
    artifact: RealModelExperimentArtifact,
    condition_kind: AblationConditionKind,
    failure: AblationConditionExecutionFailure,
) -> list[RealExperimentConditionRecord]:
    original = next(
        item
        for item in artifact.condition_records
        if item.condition_kind is condition_kind
    )
    replacement = RealExperimentConditionRecord.create(
        artifact.experiment_plan,
        condition_kind=condition_kind,
        invocation_records=original.invocation_records,
        prompt_visibility_audits=original.prompt_visibility_audits,
        condition_failure=failure,
    )
    return [
        replacement if item.condition_kind is condition_kind else item
        for item in artifact.condition_records
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
    comparison = _comparison_from_execution(plan, records)
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
        "strict_schema_bundle_sha256",
        "responses_completion_contract",
    }
    assert "base_url" not in serialized
    assert "api_key" not in serialized
    assert "secret@" not in serialized


def _schemas_by_role():
    return {
        role: reasoning_provider_output_json_schema_for_role(role)
        for role in PHASE10D_PROVIDER_ROLE_ORDER
    }


def _descriptor_with_bundle(bundle_hash: str) -> RealModelProviderDescriptor:
    source = _descriptor()
    values = {
        "provider_protocol": source.provider_protocol,
        "model": source.model,
        "api_style": source.api_style,
        "strict_json_schema": source.strict_json_schema,
        "reasoning_effort": source.reasoning_effort,
        "max_completion_tokens": source.max_completion_tokens,
        "schema_name": source.schema_name,
        "strict_schema_bundle_sha256": bundle_hash,
    }
    return RealModelProviderDescriptor(
        id=real_model_provider_descriptor_id(**values),
        **values,
    )


def _legacy_strict_descriptor() -> RealModelProviderDescriptor:
    source = _descriptor()
    identity_values = {
        "provider_protocol": source.provider_protocol,
        "model": source.model,
        "api_style": source.api_style,
        "strict_json_schema": source.strict_json_schema,
        "reasoning_effort": source.reasoning_effort,
        "max_completion_tokens": source.max_completion_tokens,
        "schema_name": source.schema_name,
    }
    return RealModelProviderDescriptor.model_validate(
        {
            "id": real_model_provider_descriptor_id(**identity_values),
            **identity_values,
        }
    )


def _legacy_strict_plan(
    execution_mode: ExperimentExecutionMode,
) -> RealModelExperimentPlan:
    manifest = _fixture_manifest()
    ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    current = RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=ablation,
        provider_descriptor=_descriptor(),
        execution_mode=execution_mode,
    )
    legacy_descriptor = _legacy_strict_descriptor()
    payload = current.model_dump(mode="json")
    payload["provider_descriptor"] = legacy_descriptor.model_dump(
        mode="json", exclude={"strict_schema_bundle_sha256"}
    )
    payload["id"] = real_model_experiment_plan_id(
        contract=current.contract,
        benchmark_manifest_id=current.benchmark_manifest_id,
        benchmark_version=current.benchmark_version,
        ablation_plan_id=current.ablation_plan_id,
        provider_descriptor_id=legacy_descriptor.id,
        execution_mode=current.execution_mode,
        condition_spec_ids=[item.id for item in current.condition_specs],
        case_ids=current.case_ids,
        provider_role_order=current.provider_role_order,
        masked_prompt_projection_contract=(
            current.masked_prompt_projection_contract
        ),
    )
    return RealModelExperimentPlan.model_validate(payload)


def _legacy_responses_descriptor() -> RealModelProviderDescriptor:
    source = _descriptor(api_style=LLMAPIStyle.RESPONSES)
    identity_values = {
        "provider_protocol": source.provider_protocol,
        "model": source.model,
        "api_style": source.api_style,
        "strict_json_schema": source.strict_json_schema,
        "reasoning_effort": source.reasoning_effort,
        "max_completion_tokens": source.max_completion_tokens,
        "schema_name": source.schema_name,
        "strict_schema_bundle_sha256": source.strict_schema_bundle_sha256,
    }
    return RealModelProviderDescriptor.model_validate(
        {
            "id": real_model_provider_descriptor_id(**identity_values),
            **identity_values,
        }
    )


def _responses_descriptor_with_contract(
    contract: str,
) -> RealModelProviderDescriptor:
    source = _descriptor(api_style=LLMAPIStyle.RESPONSES)
    values = {
        "provider_protocol": source.provider_protocol,
        "model": source.model,
        "api_style": source.api_style,
        "strict_json_schema": source.strict_json_schema,
        "reasoning_effort": source.reasoning_effort,
        "max_completion_tokens": source.max_completion_tokens,
        "schema_name": source.schema_name,
        "strict_schema_bundle_sha256": source.strict_schema_bundle_sha256,
        "responses_completion_contract": contract,
    }
    return RealModelProviderDescriptor(
        id=real_model_provider_descriptor_id(**values),
        **values,
    )


def _legacy_responses_plan(
    execution_mode: ExperimentExecutionMode,
) -> RealModelExperimentPlan:
    manifest = _fixture_manifest()
    ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    current = RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=ablation,
        provider_descriptor=_descriptor(api_style=LLMAPIStyle.RESPONSES),
        execution_mode=execution_mode,
    )
    legacy_descriptor = _legacy_responses_descriptor()
    payload = current.model_dump(mode="json")
    payload["provider_descriptor"] = legacy_descriptor.model_dump(
        mode="json", exclude={"responses_completion_contract"}
    )
    payload["id"] = real_model_experiment_plan_id(
        contract=current.contract,
        benchmark_manifest_id=current.benchmark_manifest_id,
        benchmark_version=current.benchmark_version,
        ablation_plan_id=current.ablation_plan_id,
        provider_descriptor_id=legacy_descriptor.id,
        execution_mode=current.execution_mode,
        condition_spec_ids=[item.id for item in current.condition_specs],
        case_ids=current.case_ids,
        provider_role_order=current.provider_role_order,
        masked_prompt_projection_contract=(
            current.masked_prompt_projection_contract
        ),
    )
    return RealModelExperimentPlan.model_validate(payload)


def _deepseek_descriptor() -> RealModelProviderDescriptor:
    return RealModelProviderDescriptor.from_provider_config(
        _config(
            model="deepseek-v4-flash",
            api_style=LLMAPIStyle.RESPONSES,
            reasoning_effort="none",
            max_completion_tokens=2048,
        )
    )


def _legacy_projection_plan(
    execution_mode: ExperimentExecutionMode,
) -> RealModelExperimentPlan:
    manifest = _fixture_manifest()
    ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    current = RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=ablation,
        provider_descriptor=_deepseek_descriptor(),
        execution_mode=execution_mode,
    )
    payload = current.model_dump(mode="json")
    payload.pop("masked_prompt_projection_contract")
    payload["id"] = real_model_experiment_plan_id(
        contract=current.contract,
        benchmark_manifest_id=current.benchmark_manifest_id,
        benchmark_version=current.benchmark_version,
        ablation_plan_id=current.ablation_plan_id,
        provider_descriptor_id=current.provider_descriptor.id,
        execution_mode=current.execution_mode,
        condition_spec_ids=[item.id for item in current.condition_specs],
        case_ids=current.case_ids,
        provider_role_order=current.provider_role_order,
    )
    return RealModelExperimentPlan.model_validate(payload)


def _wrong_projection_plan(
    execution_mode: ExperimentExecutionMode = (
        ExperimentExecutionMode.OFFLINE_CONTRACT
    ),
) -> RealModelExperimentPlan:
    manifest = _fixture_manifest()
    ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    current = RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=ablation,
        provider_descriptor=_descriptor(),
        execution_mode=execution_mode,
    )
    wrong_contract = "fixture-incompatible-masked-projection"
    payload = current.model_dump(mode="json")
    payload["masked_prompt_projection_contract"] = wrong_contract
    payload["id"] = real_model_experiment_plan_id(
        contract=current.contract,
        benchmark_manifest_id=current.benchmark_manifest_id,
        benchmark_version=current.benchmark_version,
        ablation_plan_id=current.ablation_plan_id,
        provider_descriptor_id=current.provider_descriptor.id,
        execution_mode=current.execution_mode,
        condition_spec_ids=[item.id for item in current.condition_specs],
        case_ids=current.case_ids,
        provider_role_order=current.provider_role_order,
        masked_prompt_projection_contract=wrong_contract,
    )
    return RealModelExperimentPlan.model_validate(payload)


def test_strict_schema_bundle_hash_is_deterministic_and_role_order_neutral():
    schemas = _schemas_by_role()
    reversed_schemas = dict(reversed(list(schemas.items())))
    canonical_payload = {
        role.value: schema for role, schema in schemas.items()
    }
    expected = hashlib.sha256(
        json.dumps(
            canonical_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()

    assert strict_schema_bundle_sha256() == expected
    assert strict_schema_bundle_sha256(schemas) == expected
    assert strict_schema_bundle_sha256(reversed_schemas) == expected


def test_schema_bundle_covers_exact_phase10d_roles(monkeypatch):
    observed = []

    def fixture_schema(role):
        observed.append(role)
        return {"type": "object", "fixture_role": role.value}

    monkeypatch.setattr(
        "chipchain.evaluation.experiment_models."
        "reasoning_provider_output_json_schema_for_role",
        fixture_schema,
    )
    strict_schema_bundle_sha256()

    assert observed == list(PHASE10D_PROVIDER_ROLE_ORDER)
    with pytest.raises(ValueError, match="exactly four"):
        strict_schema_bundle_sha256({})


def test_schema_bundle_hash_changes_when_one_role_schema_changes():
    schemas = _schemas_by_role()
    changed = deepcopy(schemas)
    changed[ReasoningAgentType.HARDWARE]["fixture_nonproduction_change"] = True

    assert strict_schema_bundle_sha256(changed) != (
        strict_schema_bundle_sha256(schemas)
    )


def test_descriptor_binds_current_schema_bundle_only_in_strict_mode():
    strict = _descriptor()
    non_strict = _descriptor(json_mode=False)

    assert strict.strict_schema_bundle_sha256 == strict_schema_bundle_sha256()
    assert non_strict.strict_schema_bundle_sha256 is None


def test_new_descriptor_binds_completion_contract_only_for_responses():
    responses = _descriptor(api_style=LLMAPIStyle.RESPONSES)
    chat = _descriptor(api_style=LLMAPIStyle.CHAT_COMPLETIONS)

    assert (
        responses.responses_completion_contract
        == PHASE10D_RESPONSES_COMPLETION_CONTRACT
    )
    assert chat.responses_completion_contract is None


def test_legacy_responses_descriptor_retains_step4_identity():
    legacy = _legacy_responses_descriptor()
    payload = legacy.model_dump(
        mode="json", exclude={"responses_completion_contract"}
    )

    restored = RealModelProviderDescriptor.model_validate(payload)

    assert "responses_completion_contract" not in payload
    assert restored.responses_completion_contract is None
    assert restored.id == payload["id"]


def test_legacy_responses_real_plan_remains_model_valid():
    legacy = _legacy_responses_plan(ExperimentExecutionMode.REAL_PROVIDER)
    payload = legacy.model_dump(mode="json")
    payload["provider_descriptor"].pop("responses_completion_contract")

    restored = RealModelExperimentPlan.model_validate(payload)

    assert restored == legacy
    assert restored.execution_mode is ExperimentExecutionMode.REAL_PROVIDER
    assert restored.provider_descriptor.responses_completion_contract is None


def test_real_responses_plan_create_requires_current_completion_contract():
    manifest = _fixture_manifest()
    ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    legacy = _legacy_responses_descriptor()
    wrong = _responses_descriptor_with_contract(
        "phase10d_responses_completion_state_fixture_wrong"
    )
    current = _descriptor(api_style=LLMAPIStyle.RESPONSES)

    for invalid in (legacy, wrong):
        with pytest.raises(
            ValueError, match="requires current completion contract"
        ):
            RealModelExperimentPlan.create(
                manifest=manifest,
                ablation_plan=ablation,
                provider_descriptor=invalid,
                execution_mode=ExperimentExecutionMode.REAL_PROVIDER,
            )

    real = RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=ablation,
        provider_descriptor=current,
        execution_mode=ExperimentExecutionMode.REAL_PROVIDER,
    )
    offline_legacy = RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=ablation,
        provider_descriptor=legacy,
        execution_mode=ExperimentExecutionMode.OFFLINE_CONTRACT,
    )

    assert (
        real.provider_descriptor.responses_completion_contract
        == PHASE10D_RESPONSES_COMPLETION_CONTRACT
    )
    assert (
        offline_legacy.provider_descriptor.responses_completion_contract
        is None
    )


def test_responses_completion_contract_changes_descriptor_and_plan_identity():
    legacy = _legacy_responses_descriptor()
    current = _descriptor(api_style=LLMAPIStyle.RESPONSES)

    assert legacy.id != current.id
    assert _plan(descriptor=legacy).id != _plan(descriptor=current).id


def test_chat_descriptor_retains_step4_identity_without_responses_contract():
    current = _descriptor(api_style=LLMAPIStyle.CHAT_COMPLETIONS)
    legacy_identity = real_model_provider_descriptor_id(
        provider_protocol=current.provider_protocol,
        model=current.model,
        api_style=current.api_style,
        strict_json_schema=current.strict_json_schema,
        reasoning_effort=current.reasoning_effort,
        max_completion_tokens=current.max_completion_tokens,
        schema_name=current.schema_name,
        strict_schema_bundle_sha256=current.strict_schema_bundle_sha256,
    )

    assert current.responses_completion_contract is None
    assert current.id == legacy_identity


def test_chat_descriptor_rejects_responses_completion_contract():
    source = _descriptor(api_style=LLMAPIStyle.CHAT_COMPLETIONS)
    values = {
        "provider_protocol": source.provider_protocol,
        "model": source.model,
        "api_style": source.api_style,
        "strict_json_schema": source.strict_json_schema,
        "reasoning_effort": source.reasoning_effort,
        "max_completion_tokens": source.max_completion_tokens,
        "schema_name": source.schema_name,
        "strict_schema_bundle_sha256": source.strict_schema_bundle_sha256,
        "responses_completion_contract": (
            PHASE10D_RESPONSES_COMPLETION_CONTRACT
        ),
    }

    with pytest.raises(ValidationError, match="Chat descriptor"):
        RealModelProviderDescriptor(
            id=real_model_provider_descriptor_id(**values),
            **values,
        )


def test_old_descriptor_without_bundle_retains_old_identity_and_plan_validity():
    restored = _legacy_strict_descriptor()
    payload = restored.model_dump(
        mode="json", exclude={"strict_schema_bundle_sha256"}
    )
    restored_plan = _plan(descriptor=restored)

    assert "strict_schema_bundle_sha256" not in payload
    assert restored.strict_schema_bundle_sha256 is None
    assert restored.id == payload["id"]
    assert RealModelExperimentPlan.model_validate_json(
        restored_plan.model_dump_json()
    ) == restored_plan


def test_legacy_real_provider_plan_json_remains_model_valid() -> None:
    restored = _legacy_strict_plan(ExperimentExecutionMode.REAL_PROVIDER)
    payload = restored.model_dump(mode="json")
    payload["provider_descriptor"].pop("strict_schema_bundle_sha256")

    roundtrip = RealModelExperimentPlan.model_validate(payload)

    assert roundtrip == restored
    assert roundtrip.execution_mode is ExperimentExecutionMode.REAL_PROVIDER
    assert roundtrip.provider_descriptor.strict_schema_bundle_sha256 is None


def test_plan_create_requires_bundle_only_for_new_strict_real_provider_plan():
    manifest = _fixture_manifest()
    ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    legacy = _legacy_strict_descriptor()

    with pytest.raises(ValueError, match="requires bundle provenance"):
        RealModelExperimentPlan.create(
            manifest=manifest,
            ablation_plan=ablation,
            provider_descriptor=legacy,
            execution_mode=ExperimentExecutionMode.REAL_PROVIDER,
        )

    offline = RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=ablation,
        provider_descriptor=legacy,
        execution_mode=ExperimentExecutionMode.OFFLINE_CONTRACT,
    )
    real = RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=ablation,
        provider_descriptor=_descriptor(),
        execution_mode=ExperimentExecutionMode.REAL_PROVIDER,
    )

    assert offline.provider_descriptor.strict_schema_bundle_sha256 is None
    assert real.provider_descriptor.strict_schema_bundle_sha256 is not None


def test_non_strict_descriptor_rejects_non_none_schema_bundle() -> None:
    source = _descriptor(json_mode=False)
    identity_values = {
        "provider_protocol": source.provider_protocol,
        "model": source.model,
        "api_style": source.api_style,
        "strict_json_schema": source.strict_json_schema,
        "reasoning_effort": source.reasoning_effort,
        "max_completion_tokens": source.max_completion_tokens,
        "schema_name": source.schema_name,
        "strict_schema_bundle_sha256": "a" * 64,
    }

    with pytest.raises(ValidationError, match="non-strict provider"):
        RealModelProviderDescriptor(
            id=real_model_provider_descriptor_id(**identity_values),
            **identity_values,
        )


def test_schema_bundle_hash_changes_descriptor_and_plan_identity():
    current = _descriptor()
    alternate_hash = (
        "f" * 64
        if current.strict_schema_bundle_sha256 != "f" * 64
        else "e" * 64
    )
    alternate = _descriptor_with_bundle(alternate_hash)

    assert current.id != alternate.id
    assert _plan(descriptor=current).id != _plan(descriptor=alternate).id


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


def test_new_plan_binds_current_masked_projection_and_changes_legacy_id() -> None:
    current = _plan()
    legacy = current.model_dump(mode="json")
    legacy.pop("masked_prompt_projection_contract")
    legacy_id = real_model_experiment_plan_id(
        contract=current.contract,
        benchmark_manifest_id=current.benchmark_manifest_id,
        benchmark_version=current.benchmark_version,
        ablation_plan_id=current.ablation_plan_id,
        provider_descriptor_id=current.provider_descriptor.id,
        execution_mode=current.execution_mode,
        condition_spec_ids=[item.id for item in current.condition_specs],
        case_ids=current.case_ids,
        provider_role_order=current.provider_role_order,
    )
    legacy["id"] = legacy_id
    restored = RealModelExperimentPlan.model_validate(legacy)

    assert current.masked_prompt_projection_contract == (
        PHASE10D_MASKED_PROMPT_PROJECTION_CONTRACT
    )
    assert current.id != legacy_id
    assert restored.id == legacy_id
    assert restored.masked_prompt_projection_contract is None


def test_ds5_legacy_plan_and_provider_id_remain_exactly_compatible() -> None:
    legacy = _legacy_projection_plan(ExperimentExecutionMode.REAL_PROVIDER)
    descriptor = legacy.provider_descriptor
    manifest = _fixture_manifest()
    ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    current = RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=ablation,
        provider_descriptor=descriptor,
        execution_mode=ExperimentExecutionMode.REAL_PROVIDER,
    )

    assert legacy.masked_prompt_projection_contract is None
    assert legacy.id == (
        "real-model-experiment-plan:"
        "b5bc602d3a78fd250fce29d191691a2ca15d83cae334fc4ec33c20f36edc401a"
    )
    assert descriptor.id == (
        "real-model-provider-descriptor:"
        "d513870cd06deaaaef40f7d4b341d70b862fbb0dc46471afbd3acb5a9eae6d9b"
    )
    assert descriptor.strict_schema_bundle_sha256 == strict_schema_bundle_sha256()
    assert descriptor.responses_completion_contract == (
        PHASE10D_RESPONSES_COMPLETION_CONTRACT
    )
    assert current.id != legacy.id
    assert current.masked_prompt_projection_contract == (
        PHASE10D_MASKED_PROMPT_PROJECTION_CONTRACT
    )


def test_offline_legacy_and_wrong_projection_plans_remain_read_compatible() -> None:
    legacy = _legacy_projection_plan(ExperimentExecutionMode.OFFLINE_CONTRACT)
    wrong = _wrong_projection_plan()

    assert RealModelExperimentPlan.model_validate_json(
        legacy.model_dump_json()
    ) == legacy
    assert wrong.masked_prompt_projection_contract == (
        "fixture-incompatible-masked-projection"
    )


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


def test_old_failure_without_parser_detail_retains_old_identity() -> None:
    plan = _one_case_plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.CODE,
    )
    identity_values = {
        "invocation_key_id": key.id,
        "stage": RealModelInvocationFailureStage.STRUCTURED_PARSE,
        "failure_code": (
            RealModelInvocationFailureCode.PROVIDER_CONTRACT_REJECTED
        ),
    }
    payload = {
        "id": real_model_invocation_failure_id(**identity_values),
        **identity_values,
        "metadata": {},
    }

    restored = RealModelInvocationFailure.model_validate(payload)

    assert "parser_failure_detail" not in payload
    assert "provider_response_failure_detail" not in payload
    assert restored.parser_failure_detail is None
    assert restored.provider_response_failure_detail is None
    assert restored.id == payload["id"]


def test_parser_failure_detail_is_closed_and_participates_in_identity() -> None:
    plan = _one_case_plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.CODE,
    )
    json_failure = RealModelInvocationFailure.create(
        key,
        stage=RealModelInvocationFailureStage.STRUCTURED_PARSE,
        failure_code=RealModelInvocationFailureCode.PROVIDER_CONTRACT_REJECTED,
        parser_failure_detail=StructuredParseFailureDetail.JSON_PARSE,
    )
    schema_failure = RealModelInvocationFailure.create(
        key,
        stage=RealModelInvocationFailureStage.STRUCTURED_PARSE,
        failure_code=RealModelInvocationFailureCode.PROVIDER_CONTRACT_REJECTED,
        parser_failure_detail=StructuredParseFailureDetail.OUTPUT_SCHEMA,
    )

    assert json_failure.id != schema_failure.id
    assert (
        RealModelInvocationFailure.model_validate_json(
            json_failure.model_dump_json()
        )
        == json_failure
    )
    with pytest.raises(ValueError, match="StructuredParseFailureDetail"):
        RealModelInvocationFailure.create(
            key,
            stage=RealModelInvocationFailureStage.STRUCTURED_PARSE,
            failure_code=(
                RealModelInvocationFailureCode.PROVIDER_CONTRACT_REJECTED
            ),
            parser_failure_detail="unbounded-fixture-detail",
        )


def test_non_parse_failure_rejects_parser_failure_detail() -> None:
    plan = _one_case_plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.CODE,
    )

    with pytest.raises(ValidationError, match="structured-parse stage"):
        RealModelInvocationFailure.create(
            key,
            stage=RealModelInvocationFailureStage.PROVIDER_TRANSPORT,
            failure_code=RealModelInvocationFailureCode.PROVIDER_TIMEOUT,
            parser_failure_detail=StructuredParseFailureDetail.JSON_PARSE,
        )


def test_provider_response_detail_is_closed_and_participates_in_identity():
    plan = _one_case_plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.CODE,
    )
    token_limit = RealModelInvocationFailure.create(
        key,
        stage=RealModelInvocationFailureStage.PROVIDER_RESPONSE,
        failure_code=RealModelInvocationFailureCode.PROVIDER_RESPONSE_INVALID,
        provider_response_failure_detail=(
            ProviderResponseFailureDetail.MAX_OUTPUT_TOKENS
        ),
    )
    filtered = RealModelInvocationFailure.create(
        key,
        stage=RealModelInvocationFailureStage.PROVIDER_RESPONSE,
        failure_code=RealModelInvocationFailureCode.PROVIDER_RESPONSE_INVALID,
        provider_response_failure_detail=(
            ProviderResponseFailureDetail.CONTENT_FILTER
        ),
    )

    assert token_limit.id != filtered.id
    assert (
        RealModelInvocationFailure.model_validate_json(
            token_limit.model_dump_json()
        )
        == token_limit
    )
    with pytest.raises(ValueError, match="ProviderResponseFailureDetail"):
        RealModelInvocationFailure.create(
            key,
            stage=RealModelInvocationFailureStage.PROVIDER_RESPONSE,
            failure_code=(
                RealModelInvocationFailureCode.PROVIDER_RESPONSE_INVALID
            ),
            provider_response_failure_detail="fixture-unbounded-detail",
        )


def test_provider_response_detail_rejects_wrong_stage_or_parser_combination():
    plan = _one_case_plan()
    key = ExperimentCaseInvocationKey.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        benchmark_case_id=plan.case_ids[0],
        role=ReasoningAgentType.CODE,
    )

    with pytest.raises(ValidationError, match="provider-response stage"):
        RealModelInvocationFailure.create(
            key,
            stage=RealModelInvocationFailureStage.PROVIDER_TRANSPORT,
            failure_code=RealModelInvocationFailureCode.PROVIDER_TIMEOUT,
            provider_response_failure_detail=(
                ProviderResponseFailureDetail.MAX_OUTPUT_TOKENS
            ),
        )
    with pytest.raises(ValidationError, match="details are exclusive"):
        RealModelInvocationFailure.create(
            key,
            stage=RealModelInvocationFailureStage.PROVIDER_RESPONSE,
            failure_code=(
                RealModelInvocationFailureCode.PROVIDER_RESPONSE_INVALID
            ),
            parser_failure_detail=StructuredParseFailureDetail.JSON_PARSE,
            provider_response_failure_detail=(
                ProviderResponseFailureDetail.MAX_OUTPUT_TOKENS
            ),
        )


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
    comparison = _comparison_from_execution(
        artifact.experiment_plan, records
    )
    invalid = RealModelExperimentArtifact.create(
        experiment_plan=artifact.experiment_plan,
        condition_records=records,
        ablation_comparison_report=comparison,
    )

    assert invalid.prompt_visibility_valid is False
    assert comparison.full_context_verification_hit_rate == (
        artifact.ablation_comparison_report.full_context_verification_hit_rate
    )
    assert comparison.masked_context_verification_hit_rate == (
        artifact.ablation_comparison_report.masked_context_verification_hit_rate
    )


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


def test_comparison_children_exactly_match_execution_provenance() -> None:
    artifact = _successful_artifact()
    execution = {
        item.condition_kind: item for item in artifact.condition_records
    }
    comparison = {
        item.condition_kind: item
        for item in artifact.ablation_comparison_report.condition_results
    }

    for condition in (
        AblationConditionKind.FULL_CONTEXT_MODEL,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        AblationConditionKind.NO_MODEL_BASELINE,
    ):
        assert comparison[condition].benchmark_evaluation_report.id == (
            execution[condition].benchmark_evaluation_report.id
        )
    upper = AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND
    assert comparison[upper].context_objective_upper_bound_result.id == (
        execution[upper].context_objective_upper_bound_result.id
    )
    masked = AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
    assert comparison[masked].prompt_visibility_audit_ids == sorted(
        item.id for item in execution[masked].prompt_visibility_audits
    )


@pytest.mark.parametrize(
    "condition_kind",
    [
        AblationConditionKind.FULL_CONTEXT_MODEL,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        AblationConditionKind.NO_MODEL_BASELINE,
    ],
)
def test_same_benchmark_alternative_report_cannot_be_cross_wired(
    condition_kind,
) -> None:
    artifact = _successful_artifact()
    alternative_report, _ = _alternative_same_benchmark_outputs()
    execution_condition = next(
        item
        for item in artifact.condition_records
        if item.condition_kind is condition_kind
    )
    assert alternative_report.benchmark_manifest_id == (
        artifact.experiment_plan.benchmark_manifest_id
    )
    assert alternative_report.id != (
        execution_condition.benchmark_evaluation_report.id
    )
    assert alternative_report.negative_control_false_positive_rate.id != (
        execution_condition.benchmark_evaluation_report
        .negative_control_false_positive_rate.id
    )
    replacement = AblationConditionResult.create(
        ablation_plan_id=artifact.experiment_plan.ablation_plan_id,
        condition_kind=condition_kind,
        benchmark_manifest_id=artifact.experiment_plan.benchmark_manifest_id,
        benchmark_evaluation_report=alternative_report,
        prompt_visibility_audit_ids=[
            audit.id
            for audit in execution_condition.prompt_visibility_audits
        ],
    )
    comparison = _comparison_with_condition_result(artifact, replacement)

    with pytest.raises(ValidationError, match="condition output ID mismatch"):
        RealModelExperimentArtifact.create(
            experiment_plan=artifact.experiment_plan,
            condition_records=artifact.condition_records,
            ablation_comparison_report=comparison,
        )


def test_same_benchmark_alternative_upper_result_cannot_be_cross_wired() -> None:
    artifact = _successful_artifact()
    _, alternative_upper = _alternative_same_benchmark_outputs()
    upper_kind = AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND
    execution_upper = next(
        item
        for item in artifact.condition_records
        if item.condition_kind is upper_kind
    )
    assert alternative_upper.benchmark_manifest_id == (
        artifact.experiment_plan.benchmark_manifest_id
    )
    assert alternative_upper.id != (
        execution_upper.context_objective_upper_bound_result.id
    )
    assert alternative_upper.rate.id != (
        execution_upper.context_objective_upper_bound_result.rate.id
    )
    replacement = AblationConditionResult.create(
        ablation_plan_id=artifact.experiment_plan.ablation_plan_id,
        condition_kind=upper_kind,
        benchmark_manifest_id=artifact.experiment_plan.benchmark_manifest_id,
        context_objective_upper_bound_result=alternative_upper,
    )
    comparison = _comparison_with_condition_result(artifact, replacement)

    with pytest.raises(ValidationError, match="condition output ID mismatch"):
        RealModelExperimentArtifact.create(
            experiment_plan=artifact.experiment_plan,
            condition_records=artifact.condition_records,
            ablation_comparison_report=comparison,
        )


def test_masked_comparison_requires_exact_execution_audit_ids() -> None:
    artifact = _successful_artifact()
    masked_kind = AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
    masked = next(
        item
        for item in artifact.condition_records
        if item.condition_kind is masked_kind
    )
    replacement = AblationConditionResult.create(
        ablation_plan_id=artifact.experiment_plan.ablation_plan_id,
        condition_kind=masked_kind,
        benchmark_manifest_id=artifact.experiment_plan.benchmark_manifest_id,
        benchmark_evaluation_report=masked.benchmark_evaluation_report,
        prompt_visibility_audit_ids=[
            audit.id for audit in masked.prompt_visibility_audits[:-1]
        ],
    )
    comparison = _comparison_with_condition_result(artifact, replacement)

    with pytest.raises(ValidationError, match="prompt-audit provenance"):
        RealModelExperimentArtifact.create(
            experiment_plan=artifact.experiment_plan,
            condition_records=artifact.condition_records,
            ablation_comparison_report=comparison,
        )


def test_same_prompt_sha_different_audit_artifact_cannot_be_substituted() -> None:
    artifact = _successful_artifact()
    masked_kind = AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
    masked = next(
        item
        for item in artifact.condition_records
        if item.condition_kind is masked_kind
    )
    prompt = _prompt(
        artifact.experiment_plan.case_ids[0],
        ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
        ReasoningAgentType.CODE,
    )
    alternative_audit = PromptVisibilityAuditor.audit(
        prompt,
        hidden_reference_ids=["fixture-alternative-hidden-reference"],
    )
    original_audit = next(
        item
        for item in masked.prompt_visibility_audits
        if item.prompt_sha256 == alternative_audit.prompt_sha256
    )
    assert alternative_audit.id != original_audit.id
    audit_ids = [
        alternative_audit.id if item.id == original_audit.id else item.id
        for item in masked.prompt_visibility_audits
    ]
    replacement = AblationConditionResult.create(
        ablation_plan_id=artifact.experiment_plan.ablation_plan_id,
        condition_kind=masked_kind,
        benchmark_manifest_id=artifact.experiment_plan.benchmark_manifest_id,
        benchmark_evaluation_report=masked.benchmark_evaluation_report,
        prompt_visibility_audit_ids=audit_ids,
    )
    comparison = _comparison_with_condition_result(artifact, replacement)

    with pytest.raises(ValidationError, match="prompt-audit provenance"):
        RealModelExperimentArtifact.create(
            experiment_plan=artifact.experiment_plan,
            condition_records=artifact.condition_records,
            ablation_comparison_report=comparison,
        )


@pytest.mark.parametrize(
    "condition_kind",
    [
        AblationConditionKind.FULL_CONTEXT_MODEL,
        AblationConditionKind.NO_MODEL_BASELINE,
        AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND,
    ],
)
def test_non_masked_comparison_cannot_acquire_prompt_audit_ids(
    condition_kind,
) -> None:
    artifact = _successful_artifact()
    execution = next(
        item
        for item in artifact.condition_records
        if item.condition_kind is condition_kind
    )
    replacement = AblationConditionResult.create(
        ablation_plan_id=artifact.experiment_plan.ablation_plan_id,
        condition_kind=condition_kind,
        benchmark_manifest_id=artifact.experiment_plan.benchmark_manifest_id,
        benchmark_evaluation_report=execution.benchmark_evaluation_report,
        context_objective_upper_bound_result=(
            execution.context_objective_upper_bound_result
        ),
        prompt_visibility_audit_ids=[
            "prompt-visibility-audit:fixture-unrelated"
        ],
    )
    comparison = _comparison_with_condition_result(artifact, replacement)

    with pytest.raises(ValidationError, match="prompt-audit provenance"):
        RealModelExperimentArtifact.create(
            experiment_plan=artifact.experiment_plan,
            condition_records=artifact.condition_records,
            ablation_comparison_report=comparison,
        )


def test_execution_success_cannot_bind_comparison_failure() -> None:
    artifact = _successful_artifact()
    condition_kind = AblationConditionKind.FULL_CONTEXT_MODEL
    failure = _condition_failure(artifact.experiment_plan, condition_kind)
    replacement = AblationConditionResult.create(
        ablation_plan_id=artifact.experiment_plan.ablation_plan_id,
        condition_kind=condition_kind,
        benchmark_manifest_id=artifact.experiment_plan.benchmark_manifest_id,
        execution_failure=failure,
    )
    comparison = _comparison_with_condition_result(artifact, replacement)

    with pytest.raises(ValidationError, match="success/failure provenance"):
        RealModelExperimentArtifact.create(
            experiment_plan=artifact.experiment_plan,
            condition_records=artifact.condition_records,
            ablation_comparison_report=comparison,
        )


def test_execution_failure_cannot_bind_comparison_success() -> None:
    artifact = _successful_artifact()
    condition_kind = AblationConditionKind.FULL_CONTEXT_MODEL
    failure = _condition_failure(artifact.experiment_plan, condition_kind)
    failed_records = _execution_records_with_failure(
        artifact, condition_kind, failure
    )

    with pytest.raises(ValidationError, match="success/failure provenance"):
        RealModelExperimentArtifact.create(
            experiment_plan=artifact.experiment_plan,
            condition_records=failed_records,
            ablation_comparison_report=artifact.ablation_comparison_report,
        )


def test_different_condition_failure_id_cannot_be_cross_wired() -> None:
    artifact = _successful_artifact()
    condition_kind = AblationConditionKind.FULL_CONTEXT_MODEL
    execution_failure = _condition_failure(
        artifact.experiment_plan, condition_kind
    )
    comparison_failure = _condition_failure(
        artifact.experiment_plan, condition_kind, alternate=True
    )
    failed_records = _execution_records_with_failure(
        artifact, condition_kind, execution_failure
    )
    phase10c_results = _phase10c_results_from_execution(
        artifact.experiment_plan, failed_records
    )
    replacement = AblationConditionResult.create(
        ablation_plan_id=artifact.experiment_plan.ablation_plan_id,
        condition_kind=condition_kind,
        benchmark_manifest_id=artifact.experiment_plan.benchmark_manifest_id,
        execution_failure=comparison_failure,
    )
    comparison = AblationComparisonBuilder.compare(
        _ablation_plan_for_experiment(artifact.experiment_plan),
        [
            replacement
            if item.condition_kind is condition_kind
            else item
            for item in phase10c_results
        ],
    )

    with pytest.raises(ValidationError, match="condition failure ID mismatch"):
        RealModelExperimentArtifact.create(
            experiment_plan=artifact.experiment_plan,
            condition_records=failed_records,
            ablation_comparison_report=comparison,
        )


def test_exact_condition_failure_id_cross_binding_is_accepted() -> None:
    artifact = _successful_artifact()
    condition_kind = AblationConditionKind.FULL_CONTEXT_MODEL
    failure = _condition_failure(artifact.experiment_plan, condition_kind)
    failed_records = _execution_records_with_failure(
        artifact, condition_kind, failure
    )
    comparison = _comparison_from_execution(
        artifact.experiment_plan, failed_records
    )
    accepted = RealModelExperimentArtifact.create(
        experiment_plan=artifact.experiment_plan,
        condition_records=list(reversed(failed_records)),
        ablation_comparison_report=comparison,
        metadata={"fixture_note": "identity-neutral"},
    )

    full_result = next(
        item
        for item in accepted.ablation_comparison_report.condition_results
        if item.condition_kind is condition_kind
    )
    assert full_result.execution_failure.id == failure.id
    assert accepted.execution_complete is False


@pytest.mark.parametrize(
    "condition_kind",
    [
        AblationConditionKind.FULL_CONTEXT_MODEL,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
    ],
)
def test_incomplete_role_execution_requires_failure_before_comparison(
    condition_kind,
) -> None:
    artifact = _successful_artifact()
    invocation_records, audits = _fail_stop_invocations(
        artifact.experiment_plan,
        condition_kind,
        failed_case_id=artifact.experiment_plan.case_ids[0],
        failed_role=ReasoningAgentType.HARDWARE,
    )
    incomplete_condition = RealExperimentConditionRecord.create(
        artifact.experiment_plan,
        condition_kind=condition_kind,
        invocation_records=invocation_records,
        prompt_visibility_audits=audits,
    )
    incomplete_records = [
        incomplete_condition
        if item.condition_kind is condition_kind
        else item
        for item in artifact.condition_records
    ]
    without_comparison = RealModelExperimentArtifact.create(
        experiment_plan=artifact.experiment_plan,
        condition_records=incomplete_records,
    )

    assert without_comparison.ablation_comparison_report is None
    assert without_comparison.execution_complete is False
    with pytest.raises(ValidationError, match="explicit failure for incomplete"):
        RealModelExperimentArtifact.create(
            experiment_plan=artifact.experiment_plan,
            condition_records=incomplete_records,
            ablation_comparison_report=artifact.ablation_comparison_report,
        )


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
