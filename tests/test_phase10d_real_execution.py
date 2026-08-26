"""Offline Phase 10D Step 2 execution-harness tests."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from chipchain.agents import AgentWorkflow, ReasoningContext
from chipchain.cli import main
from chipchain.evaluation import (
    AblationConditionFailureCode,
    AblationConditionFailureStage,
    AblationConditionKind,
    AblationExperimentPlan,
    BenchmarkCaseRunDisposition,
    BenchmarkEvaluationRunner,
    BenchmarkExecutionFailureCode,
    BenchmarkExecutionStage,
    ContextObjectiveUpperBoundEvaluator,
    ExperimentExecutionMode,
    ExperimentConditionCaseRun,
    FinalizedCandidateBuilder,
    ModelClaimBindingStatus,
    ModelInvocationDisposition,
    PromptVisibilityAuditStatus,
    RealExperimentCaseInput,
    RealExperimentInputSet,
    RealModelExecutionArchive,
    RealModelExperimentExecutor,
    RealModelExperimentPlan,
)
from chipchain.hardware_trigger.enums import TriggerabilityStatus
from chipchain.reasoning import (
    MockReasoningProvider,
    OpenAICompatibleLLMProvider,
    OpenAICompatibleReasoningProvider,
    ReasoningAgentType,
    ReasoningProvider,
    RoleBasedReasoningPromptBuilder,
)
from chipchain.reasoning.models import (
    REASONING_PROVIDER_SCHEMA_NAME,
    StructuredPromptRequest,
)
from chipchain.evaluation.execution_models import (
    _validate_real_provider_prompt_provenance,
)
from tests.test_phase10b_benchmark_evaluation import _fixture_manifest
from tests.test_phase10b_benchmark_evaluation import _triggerability
from tests.test_phase10c_ablation import _context
from tests.test_phase10d_experiment_contracts import _config, _descriptor


class _CountingProvider(ReasoningProvider):
    def __init__(
        self,
        *,
        fail_call: int | None = None,
        invalid_json_call: int | None = None,
        wrong_claim: bool = False,
        visibility_sensitive: bool = False,
    ) -> None:
        self.calls = []
        self._delegate = MockReasoningProvider()
        self._fail_call = fail_call
        self._invalid_json_call = invalid_json_call
        self._wrong_claim = wrong_claim
        self._visibility_sensitive = visibility_sensitive

    def generate(self, request):
        self.calls.append(request)
        call_number = len(self.calls)
        if call_number == self._fail_call:
            raise TimeoutError("offline fixture timeout")
        if call_number == self._invalid_json_call:
            return "fixture-invalid-json"
        raw = self._delegate.generate(request)
        if self._visibility_sensitive:
            payload = json.loads(raw)
            prompt_payload = json.loads(request.user_prompt)
            payload["hypothesis"]["description"] += (
                " via "
                f"{prompt_payload.get('prompt_visibility', 'full_context')}"
            )
            raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if (
            self._wrong_claim
            and request.role == ReasoningAgentType.ATTACK_CHAIN.value
        ):
            payload = json.loads(raw)
            payload["hypothesis"]["chain_claim"] = {
                "affected_execution_ids": [],
                "fault_state_ids": [],
                "hardware_resource_ids": [],
                "initiating_vulnerability_ids": [],
                "interaction_type": "firmware_behavior_to_hardware",
                "propagation_behavior_ids": [],
                "security_mechanism_ids": [],
                "target_vulnerability_ids": ["synthetic-wrong-target"],
                "trigger_behavior_ids": ["synthetic-wrong-trigger"],
            }
            return json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return raw


class _LeakingPromptBuilder(RoleBasedReasoningPromptBuilder):
    def build(self, context, *, role, visibility):
        prompt = super().build(
            context, role=role, visibility=visibility
        )
        if visibility.value == "masked_chain_context":
            prompt.system_prompt += f" leaked={context.cross_layer_interaction.id}"
        return prompt


class _OfflineChatCompletions:
    def __init__(self, *, fail_call: int | None = None) -> None:
        self.calls = []
        self._fail_call = fail_call

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if len(self.calls) == self._fail_call:
            raise TimeoutError("offline fixture transport failure")
        system_prompt, user_prompt = (
            item["content"] for item in kwargs["messages"]
        )
        payload = json.loads(user_prompt)
        visible_context = payload["reasoning_context"]
        request = StructuredPromptRequest(
            candidate_id=visible_context["id"],
            architecture=visible_context["architecture"],
            role=payload["role"],
            schema_name=REASONING_PROVIDER_SCHEMA_NAME,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
        raw = MockReasoningProvider().generate(request)
        return SimpleNamespace(
            choices=[
                SimpleNamespace(message=SimpleNamespace(content=raw))
            ]
        )


class _OfflineOpenAIClient:
    def __init__(self, *, fail_call: int | None = None) -> None:
        self.completions = _OfflineChatCompletions(fail_call=fail_call)
        self.chat = SimpleNamespace(completions=self.completions)


def _offline_real_provider(*, fail_call: int | None = None):
    client = _OfflineOpenAIClient(fail_call=fail_call)
    transport = OpenAICompatibleLLMProvider(
        config=_config(),
        api_key="fixture-only-not-a-real-secret",
        client=client,
    )
    return OpenAICompatibleReasoningProvider(transport), client


def _plan_and_inputs(
    *,
    execution_mode: ExperimentExecutionMode = (
        ExperimentExecutionMode.OFFLINE_CONTRACT
    ),
):
    manifest = _fixture_manifest()
    ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    plan = RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=ablation,
        provider_descriptor=_descriptor(),
        execution_mode=execution_mode,
    )
    base = _context()
    case_inputs = []
    for case in manifest.cases:
        context = ReasoningContext.create(
            architecture=base.architecture,
            subject_id=f"synthetic-step2-{case.id}",
            affected_components=base.affected_components,
            observed_fact_ids=base.observed_fact_ids,
            available_evidence_ids=base.available_evidence_ids,
            knowledge_entry_ids=base.knowledge_entry_ids,
            dynamic_trigger_fact_reference=(
                base.dynamic_trigger_fact_reference
            ),
            attack_pattern_reference=base.attack_pattern_reference,
            cross_layer_interaction=base.cross_layer_interaction,
            metadata={"fixture": True, "synthetic": True},
        )
        case_inputs.append(
            RealExperimentCaseInput.create(
                plan,
                benchmark_case_id=case.id,
                reasoning_context=context,
                metadata={"fixture": True, "synthetic": True},
            )
        )
    inputs = RealExperimentInputSet.create(
        plan,
        case_inputs=case_inputs,
        metadata={"fixture": True, "synthetic": True},
    )
    return manifest, plan, inputs


def _condition(archive, kind):
    return next(
        item
        for item in archive.experiment_artifact.condition_records
        if item.condition_kind is kind
    )


def _alternate_input_set(plan, inputs, *, suffix):
    case_inputs = []
    for item in inputs.case_inputs:
        context = item.reasoning_context
        replacement = ReasoningContext.create(
            architecture=context.architecture,
            subject_id=f"{context.subject_id}-{suffix}",
            affected_components=context.affected_components,
            observed_fact_ids=context.observed_fact_ids,
            available_evidence_ids=context.available_evidence_ids,
            knowledge_entry_ids=context.knowledge_entry_ids,
            dynamic_trigger_fact_reference=(
                context.dynamic_trigger_fact_reference
            ),
            attack_pattern_reference=context.attack_pattern_reference,
            cross_layer_interaction=context.cross_layer_interaction,
            runtime_observations=context.runtime_observations,
            knowledge_retrieval_result=context.knowledge_retrieval_result,
            metadata={"fixture": True, "synthetic": True},
        )
        case_inputs.append(
            RealExperimentCaseInput.create(
                plan,
                benchmark_case_id=item.benchmark_case_id,
                reasoning_context=replacement,
                triggerability=item.triggerability,
                metadata={"fixture": True, "synthetic": True},
            )
        )
    return RealExperimentInputSet.create(
        plan,
        case_inputs=case_inputs,
        metadata={"fixture": True, "synthetic": True},
    )


def _triggerability_input_set(manifest, plan, inputs, *, suffix):
    cases = {item.id: item for item in manifest.cases}
    case_inputs = []
    for item in inputs.case_inputs:
        triggerability = _triggerability(
            cases[item.benchmark_case_id],
            item.reasoning_context.cross_layer_interaction,
            TriggerabilityStatus.NOT_OBSERVED_IN_RUNTIME,
            signature_id=(
                "hardware-trigger-signature:phase10d-step2-r2-"
                f"{suffix}-{item.benchmark_case_id}"
            ),
        )
        case_inputs.append(
            RealExperimentCaseInput.create(
                plan,
                benchmark_case_id=item.benchmark_case_id,
                reasoning_context=item.reasoning_context,
                triggerability=triggerability,
                metadata={"fixture": True, "synthetic": True},
            )
        )
    return RealExperimentInputSet.create(
        plan,
        case_inputs=case_inputs,
        metadata={"fixture": True, "synthetic": True},
    )


def _rebind_case_runs(archive, plan, inputs):
    input_by_case = {
        item.benchmark_case_id: item for item in inputs.case_inputs
    }
    session_by_id = {item.id: item for item in archive.reasoning_sessions}
    return [
        ExperimentConditionCaseRun.create(
            plan,
            condition_kind=item.condition_kind,
            case_input=input_by_case[item.benchmark_case_id],
            case_run_record=item.case_run_record,
            reasoning_session_binding=(
                session_by_id.get(item.reasoning_session_binding_id)
                if item.reasoning_session_binding_id is not None
                else None
            ),
        )
        for item in archive.case_run_records_by_condition
    ]


def test_input_contracts_are_detached_deterministic_and_metadata_neutral():
    _, plan, inputs = _plan_and_inputs()
    rebuilt = RealExperimentInputSet.create(
        plan,
        case_inputs=list(reversed(inputs.case_inputs)),
        metadata={"fixture": "different"},
    )
    assert rebuilt.id == inputs.id
    assert [item.benchmark_case_id for item in rebuilt.case_inputs] == plan.case_ids
    assert "ground_truth" not in RealExperimentCaseInput.model_fields


def test_input_set_rejects_missing_case_and_other_plan_binding():
    manifest, plan, inputs = _plan_and_inputs()
    with pytest.raises(ValueError, match="exactly match"):
        RealExperimentInputSet.create(
            plan, case_inputs=inputs.case_inputs[:-1]
        )

    other_ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    other_plan = RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=other_ablation,
        provider_descriptor=_descriptor(model="fixture-other-model"),
        execution_mode=ExperimentExecutionMode.OFFLINE_CONTRACT,
    )
    with pytest.raises(ValueError, match="another plan"):
        RealExperimentInputSet.create(
            other_plan, case_inputs=inputs.case_inputs
        )


def test_offline_end_to_end_accounts_exact_calls_and_same_context():
    manifest, plan, inputs = _plan_and_inputs()
    provider = _CountingProvider()
    archive = RealModelExperimentExecutor(provider=provider).execute(
        plan, manifest, inputs
    )
    full = _condition(archive, AblationConditionKind.FULL_CONTEXT_MODEL)
    masked = _condition(
        archive, AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
    )
    no_model = _condition(archive, AblationConditionKind.NO_MODEL_BASELINE)
    upper = _condition(
        archive, AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND
    )

    assert len(provider.calls) == 16
    assert len(full.invocation_records) == 8
    assert len(masked.invocation_records) == 8
    assert all(
        item.disposition is ModelInvocationDisposition.COMPLETED
        for item in full.invocation_records + masked.invocation_records
    )
    assert no_model.invocation_records == upper.invocation_records == []
    assert archive.experiment_artifact.execution_complete
    assert archive.experiment_artifact.prompt_visibility_valid
    assert all(
        item.provider_descriptor_id == plan.provider_descriptor.id
        for item in full.invocation_records + masked.invocation_records
    )
    no_model_runs = [
        item.case_run_record
        for item in archive.case_run_records_by_condition
        if item.condition_kind is AblationConditionKind.NO_MODEL_BASELINE
    ]
    assert all(
        item.candidate_bundle.candidate.model_authored_chain_claim is None
        and item.candidate_bundle.claim_binding.status
        is ModelClaimBindingStatus.MISSING
        for item in no_model_runs
    )
    assert (
        ContextObjectiveUpperBoundEvaluator()
        .evaluate(manifest, no_model_runs)
        .id
        == upper.context_objective_upper_bound_result.id
    )
    sessions = {
        (item.condition_kind, item.benchmark_case_id): item.reasoning_session
        for item in archive.reasoning_sessions
    }
    for case_id in plan.case_ids:
        input_context_id = next(
            item.reasoning_context.id
            for item in inputs.case_inputs
            if item.benchmark_case_id == case_id
        )
        assert all(
            sessions[(condition, case_id)].reasoning_context.id
            == input_context_id
            for condition in (
                AblationConditionKind.FULL_CONTEXT_MODEL,
                AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
                AblationConditionKind.NO_MODEL_BASELINE,
            )
        )
        full_hashes = [
            item.prompt_sha256
            for item in full.invocation_records
            if item.invocation_key.benchmark_case_id == case_id
        ]
        masked_hashes = [
            item.prompt_sha256
            for item in masked.invocation_records
            if item.invocation_key.benchmark_case_id == case_id
        ]
        assert all(
            full_hash != masked_hash
            for full_hash, masked_hash in zip(
                full_hashes, masked_hashes, strict=True
            )
        )


def test_provider_failure_is_case_local_and_preserves_fail_stop_shape():
    manifest, plan, inputs = _plan_and_inputs()
    provider = _CountingProvider(fail_call=2)
    archive = RealModelExperimentExecutor(provider=provider).execute(
        plan, manifest, inputs
    )
    full = _condition(archive, AblationConditionKind.FULL_CONTEXT_MODEL)
    first_case = [
        item
        for item in full.invocation_records
        if item.invocation_key.benchmark_case_id == plan.case_ids[0]
    ]
    second_case = [
        item
        for item in full.invocation_records
        if item.invocation_key.benchmark_case_id == plan.case_ids[1]
    ]
    assert [item.disposition for item in first_case] == [
        ModelInvocationDisposition.COMPLETED,
        ModelInvocationDisposition.FAILED,
        ModelInvocationDisposition.NOT_ATTEMPTED,
        ModelInvocationDisposition.NOT_ATTEMPTED,
    ]
    assert all(
        item.disposition is ModelInvocationDisposition.COMPLETED
        for item in second_case
    )
    assert full.benchmark_evaluation_report is None
    assert full.condition_failure is not None
    assert full.condition_failure.stage is AblationConditionFailureStage.PROVIDER
    assert (
        full.condition_failure.failure_code
        is AblationConditionFailureCode.PROVIDER_UNAVAILABLE
    )
    assert not archive.experiment_artifact.execution_complete


def test_parse_failure_retains_hashes_but_not_raw_response():
    manifest, plan, inputs = _plan_and_inputs()
    provider = _CountingProvider(invalid_json_call=3)
    archive = RealModelExperimentExecutor(provider=provider).execute(
        plan, manifest, inputs
    )
    full = _condition(archive, AblationConditionKind.FULL_CONTEXT_MODEL)
    failed = next(
        item
        for item in full.invocation_records
        if item.disposition is ModelInvocationDisposition.FAILED
    )
    assert failed.prompt_sha256 is not None
    assert failed.provider_response_sha256 is not None
    assert failed.failure.stage.value == "structured_parse"
    assert (
        full.condition_failure.stage
        is AblationConditionFailureStage.ORCHESTRATION
    )
    assert (
        full.condition_failure.failure_code
        is AblationConditionFailureCode.CONDITION_ORCHESTRATION_FAILED
    )
    serialized = archive.model_dump_json()
    assert "fixture-invalid-json" not in serialized
    assert "system_prompt" not in serialized
    assert "user_prompt" not in serialized


def test_masked_leak_fails_before_provider_transport():
    manifest, plan, inputs = _plan_and_inputs()
    provider = _CountingProvider()
    archive = RealModelExperimentExecutor(
        provider=provider,
        prompt_builder_factory=_LeakingPromptBuilder,
    ).execute(plan, manifest, inputs)
    masked = _condition(
        archive, AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
    )
    failed = next(
        item
        for item in masked.invocation_records
        if item.disposition is ModelInvocationDisposition.FAILED
    )
    assert failed.failure.failure_code.value == "prompt_visibility_failed"
    assert failed.prompt_sha256 is not None
    assert failed.provider_response_sha256 is None
    assert any(
        audit.status is not PromptVisibilityAuditStatus.PASS
        for audit in masked.prompt_visibility_audits
    )
    # Eight FULL calls plus zero leaked-role transports; later cases are audited.
    assert len(provider.calls) == 8
    assert not archive.experiment_artifact.prompt_visibility_valid


def test_wrong_model_claim_is_completed_semantic_mismatch():
    manifest, plan, inputs = _plan_and_inputs()
    archive = RealModelExperimentExecutor(
        provider=_CountingProvider(wrong_claim=True)
    ).execute(plan, manifest, inputs)
    full = _condition(archive, AblationConditionKind.FULL_CONTEXT_MODEL)
    assert all(
        item.disposition is ModelInvocationDisposition.COMPLETED
        for item in full.invocation_records
    )
    assert full.benchmark_evaluation_report is not None
    full_runs = [
        item.case_run_record
        for item in archive.case_run_records_by_condition
        if item.condition_kind is AblationConditionKind.FULL_CONTEXT_MODEL
    ]
    assert all(
        item.candidate_bundle.claim_binding.status
        is ModelClaimBindingStatus.MISMATCHED
        for item in full_runs
    )


def test_archive_rejects_cross_wired_session_and_contains_no_transport_config():
    manifest, plan, inputs = _plan_and_inputs()
    archive = RealModelExperimentExecutor(
        provider=_CountingProvider()
    ).execute(plan, manifest, inputs)
    payload = archive.model_dump(mode="json")
    first, second = payload["reasoning_sessions"][:2]
    first["benchmark_case_id"], second["benchmark_case_id"] = (
        second["benchmark_case_id"],
        first["benchmark_case_id"],
    )
    with pytest.raises(ValidationError):
        RealModelExecutionArchive.model_validate(payload)
    serialized = archive.model_dump_json().lower()
    assert "fixture-provider.invalid" not in serialized
    assert "authorization" not in serialized
    assert "api_key" not in serialized


def test_archive_rejects_valid_masked_run_reassigned_to_full_condition():
    manifest, plan, inputs = _plan_and_inputs()
    archive = RealModelExperimentExecutor(
        provider=_CountingProvider(visibility_sensitive=True)
    ).execute(plan, manifest, inputs)
    case_id = plan.case_ids[0]
    full_session = next(
        item
        for item in archive.reasoning_sessions
        if item.condition_kind is AblationConditionKind.FULL_CONTEXT_MODEL
        and item.benchmark_case_id == case_id
    )
    masked_run = next(
        item.case_run_record
        for item in archive.case_run_records_by_condition
        if item.condition_kind
        is AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
        and item.benchmark_case_id == case_id
    )
    replacement = ExperimentConditionCaseRun.create(
        plan,
        condition_kind=AblationConditionKind.FULL_CONTEXT_MODEL,
        case_input=next(
            item
            for item in inputs.case_inputs
            if item.benchmark_case_id == case_id
        ),
        case_run_record=masked_run,
        reasoning_session_binding=full_session,
    )
    payload = archive.model_dump(mode="json")
    payload["case_run_records_by_condition"] = [
        replacement.model_dump(mode="json")
        if item["condition_kind"] == "full_context_model"
        and item["benchmark_case_id"] == case_id
        else item
        for item in payload["case_run_records_by_condition"]
    ]
    # Recompute only the top-level ID so rejection proves semantic cross-binding.
    from chipchain.evaluation import real_model_execution_archive_id

    payload["id"] = real_model_execution_archive_id(
        contract=payload["contract"],
        experiment_plan_id=payload["experiment_plan_id"],
        benchmark_manifest_id=payload["benchmark_manifest"]["id"],
        input_set_id=payload["input_set"]["id"],
        experiment_artifact_id=payload["experiment_artifact"]["id"],
        reasoning_session_binding_ids=[
            item["id"] for item in payload["reasoning_sessions"]
        ],
        archived_case_run_binding_ids=[
            item["id"]
            for item in payload["case_run_records_by_condition"]
        ],
    )
    with pytest.raises(ValidationError, match="candidate case run and session"):
        RealModelExecutionArchive.model_validate(payload)


def test_archive_rejects_alternate_input_set_under_the_same_plan():
    manifest, plan, input_set_a = _plan_and_inputs()
    input_set_b = _alternate_input_set(plan, input_set_a, suffix="alternate")
    assert input_set_a.id != input_set_b.id
    assert all(
        left.reasoning_context.id != right.reasoning_context.id
        for left, right in zip(
            input_set_a.case_inputs, input_set_b.case_inputs, strict=True
        )
    )
    archive_b = RealModelExperimentExecutor(
        provider=_CountingProvider()
    ).execute(plan, manifest, input_set_b)

    with pytest.raises(
        ValidationError,
        match="session reasoning context does not match case input",
    ):
        RealModelExecutionArchive.create(
            manifest=archive_b.benchmark_manifest,
            input_set=input_set_a,
            experiment_artifact=archive_b.experiment_artifact,
            reasoning_sessions=archive_b.reasoning_sessions,
            case_run_records_by_condition=(
                archive_b.case_run_records_by_condition
            ),
        )


def test_same_context_different_triggerability_cannot_cross_wire_archive():
    manifest, plan, base_inputs = _plan_and_inputs()
    input_set_a = _triggerability_input_set(
        manifest, plan, base_inputs, suffix="a"
    )
    input_set_b = _triggerability_input_set(
        manifest, plan, base_inputs, suffix="b"
    )
    assert all(
        left.reasoning_context.id == right.reasoning_context.id
        and left.triggerability.id != right.triggerability.id
        and left.id != right.id
        for left, right in zip(
            input_set_a.case_inputs, input_set_b.case_inputs, strict=True
        )
    )
    archive_b = RealModelExperimentExecutor(
        provider=_CountingProvider()
    ).execute(plan, manifest, input_set_b)
    inputs_b_by_case = {
        item.benchmark_case_id: item for item in input_set_b.case_inputs
    }
    for wrapped in archive_b.case_run_records_by_condition:
        case_input = inputs_b_by_case[wrapped.benchmark_case_id]
        assert wrapped.case_input_id == case_input.id
        if (
            wrapped.case_run_record.disposition
            is BenchmarkCaseRunDisposition.CANDIDATE
        ):
            assert (
                wrapped.case_run_record.candidate_bundle.triggerability.id
                == case_input.triggerability.id
            )

    with pytest.raises(
        ValidationError,
        match="case run does not match exact case input",
    ):
        RealModelExecutionArchive.create(
            manifest=archive_b.benchmark_manifest,
            input_set=input_set_a,
            experiment_artifact=archive_b.experiment_artifact,
            reasoning_sessions=archive_b.reasoning_sessions,
            case_run_records_by_condition=(
                archive_b.case_run_records_by_condition
            ),
        )


def test_reasoning_failure_run_retains_exact_case_input_provenance():
    manifest, plan, inputs = _plan_and_inputs()
    archive = RealModelExperimentExecutor(
        provider=_CountingProvider(fail_call=1)
    ).execute(plan, manifest, inputs)
    target_case = plan.case_ids[0]
    target_input = next(
        item
        for item in inputs.case_inputs
        if item.benchmark_case_id == target_case
    )
    failed_wrapper = next(
        item
        for item in archive.case_run_records_by_condition
        if item.condition_kind is AblationConditionKind.FULL_CONTEXT_MODEL
        and item.benchmark_case_id == target_case
    )
    assert (
        failed_wrapper.case_run_record.disposition
        is BenchmarkCaseRunDisposition.EXECUTION_FAILURE
    )
    assert failed_wrapper.reasoning_session_binding_id is None
    assert failed_wrapper.case_input_id == target_input.id

    alternate_inputs = _alternate_input_set(
        plan, inputs, suffix="failure-provenance"
    )
    alternate_input = next(
        item
        for item in alternate_inputs.case_inputs
        if item.benchmark_case_id == target_case
    )
    replacement = ExperimentConditionCaseRun.create(
        plan,
        condition_kind=failed_wrapper.condition_kind,
        case_input=alternate_input,
        case_run_record=failed_wrapper.case_run_record,
        reasoning_session_binding=None,
    )
    assert replacement.id != failed_wrapper.id
    replaced_runs = [
        replacement if item.id == failed_wrapper.id else item
        for item in archive.case_run_records_by_condition
    ]
    with pytest.raises(
        ValidationError,
        match="case run does not match exact case input",
    ):
        RealModelExecutionArchive.create(
            manifest=archive.benchmark_manifest,
            input_set=archive.input_set,
            experiment_artifact=archive.experiment_artifact,
            reasoning_sessions=archive.reasoning_sessions,
            case_run_records_by_condition=replaced_runs,
        )


@pytest.mark.parametrize("source_has_triggerability", [False, True])
def test_none_and_non_none_triggerability_substitution_fails_closed(
    source_has_triggerability,
):
    manifest, plan, none_inputs = _plan_and_inputs()
    trigger_inputs = _triggerability_input_set(
        manifest, plan, none_inputs, suffix="none-boundary"
    )
    source_inputs = trigger_inputs if source_has_triggerability else none_inputs
    archived_inputs = none_inputs if source_has_triggerability else trigger_inputs
    source = RealModelExperimentExecutor(
        provider=_CountingProvider()
    ).execute(plan, manifest, source_inputs)
    rebound_runs = _rebind_case_runs(source, plan, archived_inputs)

    with pytest.raises(
        ValidationError,
        match="candidate triggerability does not match case input",
    ):
        RealModelExecutionArchive.create(
            manifest=source.benchmark_manifest,
            input_set=archived_inputs,
            experiment_artifact=source.experiment_artifact,
            reasoning_sessions=source.reasoning_sessions,
            case_run_records_by_condition=rebound_runs,
        )


def test_real_provider_prompt_hashes_bind_exact_archived_input_without_network():
    manifest, plan, inputs = _plan_and_inputs(
        execution_mode=ExperimentExecutionMode.REAL_PROVIDER
    )
    provider, client = _offline_real_provider()
    archive = RealModelExperimentExecutor(provider=provider).execute(
        plan, manifest, inputs
    )
    assert len(client.completions.calls) == 16
    input_by_case = {
        item.benchmark_case_id: item for item in archive.input_set.case_inputs
    }
    condition_records = {
        item.condition_kind: item
        for item in archive.experiment_artifact.condition_records
    }
    _validate_real_provider_prompt_provenance(
        plan, input_by_case, condition_records
    )
    assert len(client.completions.calls) == 16

    alternate_inputs = _alternate_input_set(
        plan, inputs, suffix="real-prompt-provenance"
    )
    with pytest.raises(
        ValueError,
        match="prompt does not match archived case input",
    ):
        _validate_real_provider_prompt_provenance(
            plan,
            {
                item.benchmark_case_id: item
                for item in alternate_inputs.case_inputs
            },
            condition_records,
        )
    assert len(client.completions.calls) == 16


def test_real_provider_not_attempted_requires_no_prompt_provenance():
    manifest, plan, inputs = _plan_and_inputs(
        execution_mode=ExperimentExecutionMode.REAL_PROVIDER
    )
    provider, client = _offline_real_provider(fail_call=2)
    archive = RealModelExperimentExecutor(provider=provider).execute(
        plan, manifest, inputs
    )
    full = _condition(archive, AblationConditionKind.FULL_CONTEXT_MODEL)
    not_attempted = [
        item
        for item in full.invocation_records
        if item.disposition is ModelInvocationDisposition.NOT_ATTEMPTED
    ]
    failed = next(
        item
        for item in full.invocation_records
        if item.disposition is ModelInvocationDisposition.FAILED
    )
    assert failed.prompt_sha256 is not None
    assert not_attempted
    assert all(item.prompt_sha256 is None for item in not_attempted)
    calls_after_execution = len(client.completions.calls)
    _validate_real_provider_prompt_provenance(
        plan,
        {
            item.benchmark_case_id: item
            for item in archive.input_set.case_inputs
        },
        {
            item.condition_kind: item
            for item in archive.experiment_artifact.condition_records
        },
    )
    assert len(client.completions.calls) == calls_after_execution


def test_archive_direct_construction_detaches_caller_owned_children():
    manifest, plan, inputs = _plan_and_inputs()
    source = RealModelExperimentExecutor(
        provider=_CountingProvider()
    ).execute(plan, manifest, inputs)
    caller_input_set = RealExperimentInputSet.model_validate(
        source.input_set.model_dump(mode="json")
    )
    caller_sessions = [
        type(item).model_validate(item.model_dump(mode="json"))
        for item in source.reasoning_sessions
    ]
    caller_runs = [
        type(item).model_validate(item.model_dump(mode="json"))
        for item in source.case_run_records_by_condition
    ]
    detached = RealModelExecutionArchive(
        id=source.id,
        contract=source.contract,
        experiment_plan_id=source.experiment_plan_id,
        benchmark_manifest=source.benchmark_manifest,
        input_set=caller_input_set,
        experiment_artifact=source.experiment_artifact,
        reasoning_sessions=caller_sessions,
        case_run_records_by_condition=caller_runs,
        metadata=source.metadata,
    )
    before = detached.model_dump_json()

    caller_input_set.case_inputs[
        0
    ].reasoning_context.available_evidence_ids.append(
        "fixture-external-mutation"
    )
    caller_sessions[
        0
    ].reasoning_session.reasoning_context.observed_fact_ids.append(
        "fixture-external-session-mutation"
    )

    assert detached.model_dump_json() == before
    assert "fixture-external-mutation" not in (
        detached.input_set.case_inputs[0]
        .reasoning_context.available_evidence_ids
    )
    assert "fixture-external-session-mutation" not in (
        detached.reasoning_sessions[0]
        .reasoning_session.reasoning_context.observed_fact_ids
    )


def test_triggerability_artifact_mismatch_is_evaluation_input_failure():
    manifest, plan, inputs = _plan_and_inputs()
    first_case, second_case = manifest.cases
    first_input = next(
        item
        for item in inputs.case_inputs
        if item.benchmark_case_id == first_case.id
    )
    mismatch = _triggerability(
        second_case,
        first_input.reasoning_context.cross_layer_interaction,
        TriggerabilityStatus.NOT_OBSERVED_IN_RUNTIME,
        signature_id="hardware-trigger-signature:step2-r1-mismatch",
    )
    replaced = RealExperimentCaseInput.create(
        plan,
        benchmark_case_id=first_case.id,
        reasoning_context=first_input.reasoning_context,
        triggerability=mismatch,
        metadata={"fixture": True, "synthetic": True},
    )
    mismatch_inputs = RealExperimentInputSet.create(
        plan,
        case_inputs=[
            replaced
            if item.benchmark_case_id == first_case.id
            else item
            for item in inputs.case_inputs
        ],
    )
    archive = RealModelExperimentExecutor(
        provider=_CountingProvider()
    ).execute(plan, manifest, mismatch_inputs)
    full = _condition(archive, AblationConditionKind.FULL_CONTEXT_MODEL)
    first_run = next(
        item.case_run_record
        for item in archive.case_run_records_by_condition
        if item.condition_kind is AblationConditionKind.FULL_CONTEXT_MODEL
        and item.benchmark_case_id == first_case.id
    )
    second_run = next(
        item.case_run_record
        for item in archive.case_run_records_by_condition
        if item.condition_kind is AblationConditionKind.FULL_CONTEXT_MODEL
        and item.benchmark_case_id == second_case.id
    )
    assert first_run.execution_failure.stage is (
        BenchmarkExecutionStage.EVALUATION_INPUT_PREPARATION
    )
    assert first_run.execution_failure.failure_code is (
        BenchmarkExecutionFailureCode.EVALUATION_INPUT_INVALID
    )
    assert second_run.candidate_bundle is not None
    assert all(
        item.disposition is ModelInvocationDisposition.COMPLETED
        for item in full.invocation_records
    )
    assert (
        full.condition_failure.stage
        is AblationConditionFailureStage.ORCHESTRATION
    )


def test_candidate_builder_failure_has_exact_stage_and_keeps_invocations(
    monkeypatch,
):
    manifest, plan, inputs = _plan_and_inputs()
    original = FinalizedCandidateBuilder.from_reasoning_session
    failed = False

    def fail_once(benchmark_case_id, session):
        nonlocal failed
        if not failed:
            failed = True
            raise ValueError("bounded fixture candidate finalization failure")
        return original(benchmark_case_id, session)

    monkeypatch.setattr(
        FinalizedCandidateBuilder,
        "from_reasoning_session",
        staticmethod(fail_once),
    )
    archive = RealModelExperimentExecutor(
        provider=_CountingProvider()
    ).execute(plan, manifest, inputs)
    full = _condition(archive, AblationConditionKind.FULL_CONTEXT_MODEL)
    failed_run = next(
        item.case_run_record
        for item in archive.case_run_records_by_condition
        if item.condition_kind is AblationConditionKind.FULL_CONTEXT_MODEL
        and item.benchmark_case_id == plan.case_ids[0]
    )
    later_run = next(
        item.case_run_record
        for item in archive.case_run_records_by_condition
        if item.condition_kind is AblationConditionKind.FULL_CONTEXT_MODEL
        and item.benchmark_case_id == plan.case_ids[1]
    )
    assert failed_run.execution_failure.stage is (
        BenchmarkExecutionStage.CANDIDATE_FINALIZATION
    )
    assert failed_run.execution_failure.failure_code is (
        BenchmarkExecutionFailureCode.CANDIDATE_FINALIZATION_FAILED
    )
    assert later_run.candidate_bundle is not None
    assert all(
        item.disposition is ModelInvocationDisposition.COMPLETED
        for item in full.invocation_records
    )
    assert (
        full.condition_failure.stage
        is AblationConditionFailureStage.ORCHESTRATION
    )


def test_no_model_candidate_failure_uses_post_session_stage(monkeypatch):
    manifest, plan, inputs = _plan_and_inputs()
    original = FinalizedCandidateBuilder.from_reasoning_session
    target_case = plan.case_ids[0]

    def fail_no_model(benchmark_case_id, session):
        if (
            benchmark_case_id == target_case
            and session.metadata["orchestration_mode"]
            == "deterministic_mock"
        ):
            raise ValueError("bounded fixture no-model finalization failure")
        return original(benchmark_case_id, session)

    monkeypatch.setattr(
        FinalizedCandidateBuilder,
        "from_reasoning_session",
        staticmethod(fail_no_model),
    )
    archive = RealModelExperimentExecutor(
        provider=_CountingProvider()
    ).execute(plan, manifest, inputs)
    no_model = _condition(archive, AblationConditionKind.NO_MODEL_BASELINE)
    failed_run = next(
        item.case_run_record
        for item in archive.case_run_records_by_condition
        if item.condition_kind is AblationConditionKind.NO_MODEL_BASELINE
        and item.benchmark_case_id == target_case
    )
    assert no_model.invocation_records == []
    assert failed_run.execution_failure.stage is (
        BenchmarkExecutionStage.CANDIDATE_FINALIZATION
    )
    assert failed_run.execution_failure.failure_code is (
        BenchmarkExecutionFailureCode.CANDIDATE_FINALIZATION_FAILED
    )


def test_no_model_workflow_failure_retains_reasoning_stage(monkeypatch):
    manifest, plan, inputs = _plan_and_inputs()
    original = AgentWorkflow.execute

    def fail_deterministic_workflow(self, context):
        if type(self) is AgentWorkflow:
            raise ValueError("bounded fixture reasoning contract failure")
        return original(self, context)

    monkeypatch.setattr(AgentWorkflow, "execute", fail_deterministic_workflow)
    archive = RealModelExperimentExecutor(
        provider=_CountingProvider()
    ).execute(plan, manifest, inputs)
    no_model = _condition(archive, AblationConditionKind.NO_MODEL_BASELINE)
    no_model_runs = [
        item.case_run_record
        for item in archive.case_run_records_by_condition
        if item.condition_kind is AblationConditionKind.NO_MODEL_BASELINE
    ]
    assert no_model.invocation_records == []
    assert all(
        item.execution_failure.stage
        is BenchmarkExecutionStage.REASONING_SESSION
        and item.execution_failure.failure_code
        is BenchmarkExecutionFailureCode.REASONING_CONTRACT_FAILED
        for item in no_model_runs
    )


def test_no_model_report_failure_is_bounded_report_assembly(monkeypatch):
    manifest, plan, inputs = _plan_and_inputs()
    original = BenchmarkEvaluationRunner.evaluate

    def fail_no_model_report(self, benchmark_manifest, case_runs):
        if all(
            item.candidate_bundle.candidate.model_authored_chain_claim is None
            for item in case_runs
        ):
            raise ValueError("bounded fixture report assembly failure")
        return original(self, benchmark_manifest, case_runs)

    monkeypatch.setattr(
        BenchmarkEvaluationRunner, "evaluate", fail_no_model_report
    )
    archive = RealModelExperimentExecutor(
        provider=_CountingProvider()
    ).execute(plan, manifest, inputs)
    no_model = _condition(archive, AblationConditionKind.NO_MODEL_BASELINE)
    assert no_model.invocation_records == []
    assert (
        no_model.condition_failure.stage
        is AblationConditionFailureStage.REPORT_ASSEMBLY
    )
    assert (
        no_model.condition_failure.failure_code
        is AblationConditionFailureCode.REPORT_ASSEMBLY_FAILED
    )


def test_cli_does_not_create_provider_without_explicit_opt_in(
    monkeypatch, tmp_path
):
    called = False

    def forbidden(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("provider creation must remain unreachable")

    from chipchain.reasoning.provider import OpenAICompatibleReasoningProvider

    monkeypatch.setattr(
        OpenAICompatibleReasoningProvider, "from_env", forbidden
    )
    result = main(
        [
            "experiment",
            "real-model",
            "--manifest",
            str(tmp_path / "missing-manifest.json"),
            "--inputs",
            str(tmp_path / "missing-inputs.json"),
            "--output",
            str(tmp_path / "result.json"),
        ]
    )
    assert result == 2
    assert not called


def test_cli_opt_in_reaches_provider_factory_without_network(
    monkeypatch, tmp_path
):
    manifest, _, inputs = _plan_and_inputs()
    manifest_path = tmp_path / "manifest.json"
    inputs_path = tmp_path / "inputs.json"
    output_path = tmp_path / "archive.json"
    manifest_path.write_text(manifest.model_dump_json(), encoding="utf-8")
    inputs_path.write_text(
        json.dumps(
            {
                "case_inputs": [
                    {
                        "benchmark_case_id": item.benchmark_case_id,
                        "reasoning_context": item.reasoning_context.model_dump(
                            mode="json"
                        ),
                        "triggerability": None,
                        "metadata": {"fixture": True, "synthetic": True},
                    }
                    for item in inputs.case_inputs
                ],
                "metadata": {"fixture": True, "synthetic": True},
            }
        ),
        encoding="utf-8",
    )
    called = False

    def bounded_factory_failure(*args, **kwargs):
        nonlocal called
        called = True
        raise RuntimeError("offline fixture stopped before provider creation")

    from chipchain.reasoning.provider import OpenAICompatibleReasoningProvider

    monkeypatch.setattr(
        OpenAICompatibleReasoningProvider,
        "from_env",
        bounded_factory_failure,
    )
    result = main(
        [
            "experiment",
            "real-model",
            "--manifest",
            str(manifest_path),
            "--inputs",
            str(inputs_path),
            "--output",
            str(output_path),
            "--execute-real-provider",
        ]
    )
    assert result == 1
    assert called
    assert not output_path.exists()
