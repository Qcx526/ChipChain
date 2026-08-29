"""Phase 10D Step 8B-1C public execution wiring regressions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from chipchain.corpus import load_public_cve_corpus
from chipchain.evaluation import (
    AblationConditionKind,
    AblationExperimentPlan,
    ExperimentExecutionMode,
    PHASE10D_PUBLIC_KNOWLEDGE_EXECUTION_ARCHIVE_CONTRACT,
    PHASE10D_PUBLIC_KNOWLEDGE_EXECUTION_BINDING_CONTRACT,
    PHASE10D_STEP8B1B_FROZEN_READINESS_ID,
    PublicKnowledgeExecutionArchive,
    PublicKnowledgeExecutionBinding,
    PublicKnowledgeExecutionPreflightError,
    PublicKnowledgeRealExecutionPreflight,
    RealExperimentCaseInput,
    RealExperimentExecutionError,
    RealExperimentInputSet,
    RealModelExperimentExecutor,
    RealModelExperimentPlan,
    RealModelProviderDescriptor,
    load_public_knowledge_readiness,
    load_public_secondary_cohort,
    materialize_public_knowledge_execution_binding,
)
from chipchain.reasoning import (
    LLMAPIStyle,
    LLMProviderConfig,
    MockReasoningProvider,
    ReasoningPromptVisibility,
    StructuredPromptRequest,
)
from chipchain.reasoning.prompts import RoleBasedReasoningPromptBuilder


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "data/public_cve/arm_cross_layer_seed_v1.json"
COHORT_PATH = ROOT / "data/evaluation/public_documented_arm_secondary_v1.json"
READINESS_PATH = (
    ROOT
    / "data/evaluation/public_documented_arm_secondary_knowledge_projection_v1.json"
)
READINESS_FILE_SHA256 = (
    "c802a70e0554e0f7686f895fe8cec209ceb96220e51c7375fa07b46f3890e026"
)


class _CountingProvider(MockReasoningProvider):
    def __init__(self) -> None:
        self.calls: list[StructuredPromptRequest] = []

    def generate(self, request: StructuredPromptRequest) -> str:
        self.calls.append(request)
        return super().generate(request)


def _descriptor(model: str = "fixture-public-provider"):
    return RealModelProviderDescriptor.from_provider_config(
        LLMProviderConfig(
            base_url="https://offline.invalid/v1",
            model=model,
            api_style=LLMAPIStyle.CHAT_COMPLETIONS,
            json_mode=True,
        )
    )


def _execution_objects(*, model: str = "fixture-public-provider"):
    corpus = load_public_cve_corpus(CORPUS_PATH)
    cohort = load_public_secondary_cohort(COHORT_PATH)
    readiness = load_public_knowledge_readiness(READINESS_PATH)
    manifest = cohort.benchmark_manifest
    ablation = AblationExperimentPlan.create(
        benchmark_manifest_id=manifest.id,
        benchmark_version=manifest.benchmark_version,
    )
    plan = RealModelExperimentPlan.create(
        manifest=manifest,
        ablation_plan=ablation,
        provider_descriptor=_descriptor(model),
        execution_mode=ExperimentExecutionMode.OFFLINE_CONTRACT,
    )
    materialized = {
        item.benchmark_case_id: item for item in cohort.case_materializations
    }
    inputs = RealExperimentInputSet.create(
        plan,
        case_inputs=[
            RealExperimentCaseInput.create(
                plan,
                benchmark_case_id=case.id,
                reasoning_context=materialized[case.id].reasoning_context,
                triggerability=None,
                objective_materialization=None,
                metadata={},
            )
            for case in manifest.cases
        ],
        metadata={},
    )
    binding = materialize_public_knowledge_execution_binding(
        experiment_plan=plan,
        frozen_cohort=cohort,
        readiness_artifact=readiness,
        corpus=corpus,
        input_set=inputs,
    )
    return corpus, cohort, readiness, manifest, plan, inputs, binding


def test_exact_execution_binding_and_frozen_projection_matrix() -> None:
    _, cohort, readiness, manifest, plan, inputs, binding = _execution_objects()

    assert binding.contract == PHASE10D_PUBLIC_KNOWLEDGE_EXECUTION_BINDING_CONTRACT
    assert binding.public_knowledge_readiness_artifact.id == (
        PHASE10D_STEP8B1B_FROZEN_READINESS_ID
    )
    assert binding.experiment_plan_id == plan.id
    assert binding.benchmark_manifest_id == manifest.id
    assert binding.real_experiment_input_set_id == inputs.id
    assert len(binding.case_bindings) == 5
    assert sum(
        len(item.expected_prompt_records) for item in binding.case_bindings
    ) == 40
    assert len(binding.expected_prompt_hashes_for_archive()) == 40
    assert {
        (record.visibility, record.role)
        for item in binding.case_bindings
        for record in item.expected_prompt_records
    } == {
        (visibility, role)
        for visibility in ReasoningPromptVisibility
        for role in plan.provider_role_order
    }
    readiness_by_cve = {item.cve_id: item for item in readiness.case_readiness}
    cohort_by_cve = {item.cve_id: item for item in cohort.case_materializations}
    for item in binding.case_bindings:
        assert item.knowledge_projection.id == (
            readiness_by_cve[item.cve_id].knowledge_projection_id
        )
        assert item.reasoning_context_id == (
            cohort_by_cve[item.cve_id].reasoning_context.id
        )


def test_public_preflight_rebuilds_all_prompts_without_provider() -> None:
    _, _, _, manifest, plan, inputs, binding = _execution_objects()
    assert PublicKnowledgeRealExecutionPreflight.validate(
        experiment_plan=plan,
        manifest=manifest,
        input_set=inputs,
        binding=binding,
    ) == binding


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_readiness_id",
        "readiness_not_ready",
        "wrong_projection_id",
        "projection_content",
        "wrong_context_id",
        "wrong_knowledge_entry_id",
        "missing_prompt_hash",
        "changed_prompt_hash",
        "extra_case",
        "missing_case",
        "wrong_projection_contract",
    ],
)
def test_mutated_public_binding_fails_before_provider(mutation: str) -> None:
    _, _, _, manifest, plan, inputs, binding = _execution_objects()
    payload = binding.model_dump(mode="json")
    if mutation == "wrong_readiness_id":
        payload["public_knowledge_readiness_artifact"]["id"] = "wrong"
    elif mutation == "readiness_not_ready":
        payload["public_knowledge_readiness_artifact"]["readiness_result"] = (
            "reference_content_insufficient"
        )
    elif mutation == "wrong_projection_id":
        payload["case_bindings"][0]["knowledge_projection"]["id"] = "wrong"
    elif mutation == "projection_content":
        payload["case_bindings"][0]["knowledge_projection"]["entries"][0][
            "title"
        ] += " changed"
    elif mutation == "wrong_context_id":
        payload["case_bindings"][0]["reasoning_context_id"] = "wrong"
    elif mutation == "wrong_knowledge_entry_id":
        payload["case_bindings"][0]["knowledge_entry_id"] = "wrong"
    elif mutation == "missing_prompt_hash":
        payload["case_bindings"][0]["expected_prompt_records"].pop()
    elif mutation == "changed_prompt_hash":
        payload["case_bindings"][0]["expected_prompt_records"][0][
            "expected_prompt_sha256"
        ] = "0" * 64
    elif mutation == "extra_case":
        payload["case_bindings"].append(payload["case_bindings"][0])
    elif mutation == "missing_case":
        payload["case_bindings"].pop()
    else:
        payload["knowledge_projection_contract"] = "wrong"
    provider = _CountingProvider()
    with pytest.raises((ValueError, TypeError)):
        poisoned = PublicKnowledgeExecutionBinding.model_validate(payload)
        RealModelExperimentExecutor(
            provider=provider
        ).execute_with_public_knowledge(
            plan,
            manifest,
            inputs,
            public_knowledge_binding=poisoned,
        )
    assert provider.calls == []


def test_plan_manifest_and_input_crosswire_fail_before_provider() -> None:
    _, _, _, manifest, plan, inputs, binding = _execution_objects()
    _, _, _, _, other_plan, other_inputs, _ = _execution_objects(model="other")
    provider = _CountingProvider()
    executor = RealModelExperimentExecutor(provider=provider)
    with pytest.raises((ValueError, RealExperimentExecutionError)):
        executor.execute_with_public_knowledge(
            other_plan,
            manifest,
            other_inputs,
            public_knowledge_binding=binding,
        )
    assert provider.calls == []


def test_projected_executor_uses_official_builder_and_calls_provider_40_times(
    monkeypatch,
) -> None:
    _, _, _, manifest, plan, inputs, binding = _execution_objects()
    original = RoleBasedReasoningPromptBuilder.build_with_knowledge_projection
    calls = []

    def recording_build(self, context, **kwargs):
        calls.append((context.id, kwargs["visibility"], kwargs["role"]))
        return original(self, context, **kwargs)

    monkeypatch.setattr(
        RoleBasedReasoningPromptBuilder,
        "build_with_knowledge_projection",
        recording_build,
    )
    provider = _CountingProvider()
    wrapper = RealModelExperimentExecutor(
        provider=provider
    ).execute_with_public_knowledge(
        plan,
        manifest,
        inputs,
        public_knowledge_binding=binding,
    )
    archive = wrapper.real_model_execution_archive

    assert len(calls) == 80  # forty preflight rebuilds plus forty executions
    assert len(provider.calls) == 40
    assert len(wrapper.transport_leakage_audits) == 40
    assert wrapper.contract == PHASE10D_PUBLIC_KNOWLEDGE_EXECUTION_ARCHIVE_CONTRACT
    full = next(
        item
        for item in archive.experiment_artifact.condition_records
        if item.condition_kind is AblationConditionKind.FULL_CONTEXT_MODEL
    )
    masked = next(
        item
        for item in archive.experiment_artifact.condition_records
        if item.condition_kind is AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
    )
    no_model = next(
        item
        for item in archive.experiment_artifact.condition_records
        if item.condition_kind is AblationConditionKind.NO_MODEL_BASELINE
    )
    upper = next(
        item
        for item in archive.experiment_artifact.condition_records
        if item.condition_kind
        is AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND
    )
    assert len(full.invocation_records) == len(masked.invocation_records) == 20
    assert len(masked.prompt_visibility_audits) == 20
    assert no_model.invocation_records == upper.invocation_records == []
    for report in (
        full.benchmark_evaluation_report,
        masked.benchmark_evaluation_report,
        no_model.benchmark_evaluation_report,
    ):
        assert report is not None
        assert report.verification_hit_rate.denominator == 0
        assert report.ground_truth_chain_recall.denominator == 0
        assert report.negative_control_false_positive_rate.denominator == 0
        assert report.primary_case_coverage.denominator == 0

    serialized = wrapper.model_dump_json()
    assert '"system_prompt"' not in serialized
    assert '"user_prompt"' not in serialized
    assert '"raw_response"' not in serialized
    assert '"raw_provider_response"' not in serialized
    assert PublicKnowledgeExecutionArchive.model_validate_json(serialized) == wrapper


def test_legacy_execute_never_enters_projected_builder(monkeypatch) -> None:
    _, _, _, manifest, plan, inputs, _ = _execution_objects()

    def forbidden(*args, **kwargs):
        raise AssertionError("legacy path entered projected prompt builder")

    monkeypatch.setattr(
        RoleBasedReasoningPromptBuilder,
        "build_with_knowledge_projection",
        forbidden,
    )
    provider = _CountingProvider()
    archive = RealModelExperimentExecutor(provider=provider).execute(
        plan, manifest, inputs
    )
    assert len(provider.calls) == 40
    assert archive.input_set.id == inputs.id
    assert archive.experiment_artifact.experiment_plan.id == plan.id


def test_prompt_hash_drift_fails_in_preflight_before_provider(monkeypatch) -> None:
    _, _, _, manifest, plan, inputs, binding = _execution_objects()
    original = RoleBasedReasoningPromptBuilder.build_with_knowledge_projection

    def whitespace_drift(self, context, **kwargs):
        prompt = original(self, context, **kwargs)
        prompt.user_prompt = prompt.user_prompt.replace(":", ": ", 1)
        return prompt

    monkeypatch.setattr(
        RoleBasedReasoningPromptBuilder,
        "build_with_knowledge_projection",
        whitespace_drift,
    )
    provider = _CountingProvider()
    with pytest.raises(
        (PublicKnowledgeExecutionPreflightError, RealExperimentExecutionError)
    ):
        RealModelExperimentExecutor(
            provider=provider
        ).execute_with_public_knowledge(
            plan,
            manifest,
            inputs,
            public_knowledge_binding=binding,
        )
    assert provider.calls == []


def test_structured_leak_fails_in_preflight_before_provider(
    monkeypatch,
) -> None:
    _, _, _, manifest, plan, inputs, binding = _execution_objects()
    original = RoleBasedReasoningPromptBuilder.build_with_knowledge_projection

    def leaking(self, context, **kwargs):
        prompt = original(self, context, **kwargs)
        payload = json.loads(prompt.user_prompt)
        payload["evaluation_scope"] = "secondary_only"
        prompt.user_prompt = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return prompt

    monkeypatch.setattr(
        RoleBasedReasoningPromptBuilder,
        "build_with_knowledge_projection",
        leaking,
    )
    provider = _CountingProvider()
    with pytest.raises(
        (PublicKnowledgeExecutionPreflightError, RealExperimentExecutionError)
    ):
        RealModelExperimentExecutor(
            provider=provider
        ).execute_with_public_knowledge(
            plan,
            manifest,
            inputs,
            public_knowledge_binding=binding,
        )
    assert provider.calls == []


def test_masked_hidden_reference_leak_fails_before_provider(monkeypatch) -> None:
    _, _, _, manifest, plan, inputs, binding = _execution_objects()
    original = RoleBasedReasoningPromptBuilder.build_with_knowledge_projection

    def leaking(self, context, **kwargs):
        prompt = original(self, context, **kwargs)
        if kwargs["visibility"] is ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT:
            prompt.system_prompt += f" {context.cross_layer_interaction.id}"
        return prompt

    monkeypatch.setattr(
        RoleBasedReasoningPromptBuilder,
        "build_with_knowledge_projection",
        leaking,
    )
    provider = _CountingProvider()
    with pytest.raises(
        (PublicKnowledgeExecutionPreflightError, RealExperimentExecutionError)
    ):
        RealModelExperimentExecutor(
            provider=provider
        ).execute_with_public_knowledge(
            plan,
            manifest,
            inputs,
            public_knowledge_binding=binding,
        )
    assert provider.calls == []


def test_public_provider_failure_is_not_retried() -> None:
    _, _, _, manifest, plan, inputs, binding = _execution_objects()

    class FailsFirst(_CountingProvider):
        def generate(self, request: StructuredPromptRequest) -> str:
            self.calls.append(request)
            if len(self.calls) == 1:
                raise TimeoutError("offline failure")
            return MockReasoningProvider.generate(self, request)

    provider = FailsFirst()
    wrapper = RealModelExperimentExecutor(
        provider=provider
    ).execute_with_public_knowledge(
        plan,
        manifest,
        inputs,
        public_knowledge_binding=binding,
    )
    from chipchain.evaluation import structured_prompt_request_sha256

    prompt_hashes = [
        structured_prompt_request_sha256(item) for item in provider.calls
    ]
    assert len(provider.calls) == 37
    assert len(prompt_hashes) == len(set(prompt_hashes))
    assert len(wrapper.transport_leakage_audits) == 37


def test_preflight_script_needs_no_provider_configuration() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_public_knowledge_experiment.py",
            "--preflight-only",
        ],
        cwd=ROOT,
        env={},
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "expected_prompt_hashes=40" in result.stdout
    assert "preflight=pass" in result.stdout


def test_real_execution_requires_explicit_mode_and_output() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_public_knowledge_experiment.py",
            "--execute-real-provider",
        ],
        cwd=ROOT,
        env={},
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "requires --output" in result.stderr


def test_frozen_readiness_bytes_and_legacy_hash_are_unchanged() -> None:
    assert hashlib.sha256(READINESS_PATH.read_bytes()).hexdigest() == (
        READINESS_FILE_SHA256
    )
    _, cohort, _, _, _, _, _ = _execution_objects()
    context = cohort.case_materializations[0].reasoning_context
    prompt = RoleBasedReasoningPromptBuilder().build(
        context,
        role="code",
        visibility="full_context",
    )
    from chipchain.evaluation import structured_prompt_request_sha256

    assert structured_prompt_request_sha256(prompt) == (
        "88c63efe325d53117738e8cca5e230e476b2c2489f6e487b7e7785db990fc883"
    )
