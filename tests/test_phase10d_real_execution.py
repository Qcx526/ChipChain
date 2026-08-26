"""Offline Phase 10D Step 2 execution-harness tests."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from chipchain.agents import ReasoningContext
from chipchain.cli import main
from chipchain.evaluation import (
    AblationConditionKind,
    AblationExperimentPlan,
    ContextObjectiveUpperBoundEvaluator,
    ExperimentExecutionMode,
    ExperimentConditionCaseRun,
    ModelClaimBindingStatus,
    ModelInvocationDisposition,
    PromptVisibilityAuditStatus,
    RealExperimentCaseInput,
    RealExperimentInputSet,
    RealModelExecutionArchive,
    RealModelExperimentExecutor,
    RealModelExperimentPlan,
)
from chipchain.reasoning import (
    MockReasoningProvider,
    ReasoningAgentType,
    ReasoningProvider,
    RoleBasedReasoningPromptBuilder,
)
from tests.test_phase10b_benchmark_evaluation import _fixture_manifest
from tests.test_phase10c_ablation import _context
from tests.test_phase10d_experiment_contracts import _descriptor


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


def _plan_and_inputs():
    manifest = _fixture_manifest()
    ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    plan = RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=ablation,
        provider_descriptor=_descriptor(),
        execution_mode=ExperimentExecutionMode.OFFLINE_CONTRACT,
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
        assert (
            sessions[
                (AblationConditionKind.FULL_CONTEXT_MODEL, case_id)
            ].reasoning_context.id
            == sessions[
                (AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL, case_id)
            ].reasoning_context.id
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
