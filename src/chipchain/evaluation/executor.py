"""Opt-in Phase 10D Step 2 execution harness.

The private recorders in this module delegate to the frozen reasoning stack.
Raw prompts and provider text live only in one transient in-memory trace and are
reduced to the existing Step 1 SHA-256 provenance before an archive is built.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from chipchain.agents.errors import ProviderBackedWorkflowExecutionError
from chipchain.agents.workflow import AgentWorkflow, ProviderBackedAgentWorkflow
from chipchain.evaluation.ablation import (
    AblationComparisonBuilder,
    ContextObjectiveUpperBoundEvaluator,
)
from chipchain.evaluation.ablation_models import (
    PHASE10C_ABLATION_CONTRACT,
    AblationConditionExecutionFailure,
    AblationConditionResult,
    AblationExperimentPlan,
    PromptVisibilityAudit,
)
from chipchain.evaluation.benchmark_models import (
    BenchmarkCaseExecutionFailure,
    BenchmarkCaseRunRecord,
    CandidateEvaluationBundle,
)
from chipchain.evaluation.candidate import FinalizedCandidateBuilder
from chipchain.evaluation.claim_binding import ModelClaimBinder
from chipchain.evaluation.enums import (
    AblationConditionFailureCode,
    AblationConditionFailureStage,
    AblationConditionKind,
    BenchmarkExecutionFailureCode,
    BenchmarkExecutionStage,
    ExperimentExecutionMode,
    PromptVisibilityAuditStatus,
    ProviderResponseFailureDetail,
    RealModelInvocationFailureCode,
    RealModelInvocationFailureStage,
    StructuredParseFailureDetail,
)
from chipchain.evaluation.execution_models import (
    ExperimentCaseReasoningSession,
    ExperimentConditionCaseRun,
    RealExperimentInputSet,
    RealModelExecutionArchive,
)
from chipchain.evaluation.execution_instrumentation import (
    _PerCaseInvocationTrace,
    _PromptVisibilityLeakError,
    _PublicKnowledgePromptGateError,
    _RecordingPromptBuilder,
    _RecordingReasoningParser,
    _RecordingReasoningProvider,
)
from chipchain.evaluation.public_knowledge_execution import (
    PublicKnowledgeExecutionPreflightError,
    PublicKnowledgeRealExecutionPreflight,
)
from chipchain.evaluation.public_knowledge_execution_models import (
    PublicKnowledgeExecutionArchive,
    PublicKnowledgeExecutionBinding,
)
from chipchain.evaluation.public_knowledge_readiness_models import (
    PublicKnowledgeLeakageAudit,
)
from chipchain.evaluation.experiment_artifact import (
    RealExperimentConditionRecord,
    RealModelExperimentArtifact,
)
from chipchain.evaluation.experiment_models import (
    PHASE10D_PROVIDER_ROLE_ORDER,
    PHASE10D_RESPONSES_COMPLETION_CONTRACT,
    ExperimentCaseInvocationKey,
    ModelInvocationRecord,
    RealModelExperimentPlan,
    RealModelInvocationFailure,
    RealModelProviderDescriptor,
)
from chipchain.evaluation.models import BenchmarkManifest, EvaluationBenchmarkCase
from chipchain.evaluation.oracle import ChainFeasibilityOracle
from chipchain.evaluation.runner import BenchmarkEvaluationRunner
from chipchain.reasoning.engine import ReasoningEngine
from chipchain.reasoning.enums import (
    LLMAPIStyle,
    ProviderIncompleteReason,
    ReasoningAgentType,
    ReasoningPromptVisibility,
)
from chipchain.reasoning.errors import (
    LLMOutputValidationError,
    LLMProviderConfigurationError,
    LLMProviderResponseError,
)
from chipchain.reasoning.parser import ConstrainedReasoningOutputParser
from chipchain.reasoning.prompt_view import (
    PHASE10D_MASKED_PROMPT_PROJECTION_CONTRACT,
    masked_chain_hidden_reference_ids,
)
from chipchain.reasoning.prompts import RoleBasedReasoningPromptBuilder
from chipchain.reasoning.provider import (
    OpenAICompatibleReasoningProvider,
    ReasoningProvider,
)


class RealExperimentExecutionError(ValueError):
    """Fail-closed preflight error raised before any provider invocation."""


@dataclass
class _ConditionExecution:
    condition: AblationConditionKind
    invocation_records: list[ModelInvocationRecord] = field(default_factory=list)
    audits: list[PromptVisibilityAudit] = field(default_factory=list)
    public_knowledge_audits: list[PublicKnowledgeLeakageAudit] = field(
        default_factory=list
    )
    sessions: list[ExperimentCaseReasoningSession] = field(default_factory=list)
    case_runs: list[ExperimentConditionCaseRun] = field(default_factory=list)
    report: object | None = None
    failure: AblationConditionExecutionFailure | None = None


class RealModelExperimentExecutor:
    """Execute the frozen four-condition matrix without changing its semantics."""

    def __init__(
        self,
        *,
        provider: ReasoningProvider,
        prompt_builder_factory: Callable[[], RoleBasedReasoningPromptBuilder]
        | None = None,
    ) -> None:
        if not isinstance(provider, ReasoningProvider):
            raise TypeError("experiment executor requires ReasoningProvider")
        self._provider = provider
        self._uses_custom_prompt_builder = prompt_builder_factory is not None
        self._prompt_builder_factory = (
            prompt_builder_factory or RoleBasedReasoningPromptBuilder
        )

    def execute(
        self,
        plan: RealModelExperimentPlan,
        manifest: BenchmarkManifest,
        input_set: RealExperimentInputSet,
    ) -> RealModelExecutionArchive:
        """Run one exact plan; REAL_PROVIDER must be explicitly supplied upstream."""

        result = self._execute(
            plan,
            manifest,
            input_set,
            public_knowledge_binding=None,
        )
        if not isinstance(result, RealModelExecutionArchive):
            raise RuntimeError("legacy execution returned public wrapper")
        return result

    def execute_with_public_knowledge(
        self,
        plan: RealModelExperimentPlan,
        manifest: BenchmarkManifest,
        input_set: RealExperimentInputSet,
        *,
        public_knowledge_binding: PublicKnowledgeExecutionBinding,
    ) -> PublicKnowledgeExecutionArchive:
        """Run the explicit frozen public-projection path without fallback."""

        result = self._execute(
            plan,
            manifest,
            input_set,
            public_knowledge_binding=public_knowledge_binding,
        )
        if not isinstance(result, PublicKnowledgeExecutionArchive):
            raise RuntimeError("public execution did not return public wrapper")
        return result

    def _execute(
        self,
        plan: RealModelExperimentPlan,
        manifest: BenchmarkManifest,
        input_set: RealExperimentInputSet,
        *,
        public_knowledge_binding: PublicKnowledgeExecutionBinding | None,
    ) -> RealModelExecutionArchive | PublicKnowledgeExecutionArchive:
        """Execute one legacy or explicitly bound public experiment."""

        plan_snapshot, manifest_snapshot, inputs = self._preflight(
            plan, manifest, input_set
        )
        binding = None
        if public_knowledge_binding is not None:
            if self._uses_custom_prompt_builder:
                raise RealExperimentExecutionError(
                    "public knowledge execution requires the frozen prompt builder"
                )
            try:
                binding = PublicKnowledgeRealExecutionPreflight.validate(
                    experiment_plan=plan_snapshot,
                    manifest=manifest_snapshot,
                    input_set=inputs,
                    binding=public_knowledge_binding,
                )
            except PublicKnowledgeExecutionPreflightError as exc:
                raise RealExperimentExecutionError(str(exc)) from exc
        ablation_plan = self._ablation_plan(plan_snapshot)
        cases = {item.id: item for item in manifest_snapshot.cases}
        inputs_by_case = {
            item.benchmark_case_id: item for item in inputs.case_inputs
        }

        executions: dict[AblationConditionKind, _ConditionExecution] = {}
        for condition, visibility in (
            (
                AblationConditionKind.FULL_CONTEXT_MODEL,
                ReasoningPromptVisibility.FULL_CONTEXT,
            ),
            (
                AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
                ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
            ),
        ):
            executions[condition] = self._execute_model_condition(
                plan_snapshot,
                manifest_snapshot,
                cases,
                inputs_by_case,
                condition=condition,
                visibility=visibility,
                public_knowledge_binding=binding,
            )

        no_model = self._execute_no_model_condition(
            plan_snapshot, manifest_snapshot, cases, inputs_by_case
        )
        executions[AblationConditionKind.NO_MODEL_BASELINE] = no_model
        upper = self._execute_upper_condition(
            plan_snapshot, manifest_snapshot, no_model
        )
        executions[AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND] = upper

        condition_results = [
            self._condition_result(plan_snapshot, execution)
            for execution in executions.values()
        ]
        comparison = AblationComparisonBuilder.compare(
            ablation_plan, condition_results
        )
        condition_records = [
            self._condition_record(plan_snapshot, execution)
            for execution in executions.values()
        ]
        artifact = RealModelExperimentArtifact.create(
            experiment_plan=plan_snapshot,
            condition_records=condition_records,
            ablation_comparison_report=comparison,
            metadata={"phase10d_step2_execution": True},
        )
        sessions = [
            item
            for execution in executions.values()
            for item in execution.sessions
        ]
        runs = [
            item
            for execution in executions.values()
            for item in execution.case_runs
        ]
        archive = RealModelExecutionArchive.create(
            manifest=manifest_snapshot,
            input_set=inputs,
            experiment_artifact=artifact,
            reasoning_sessions=sessions,
            case_run_records_by_condition=runs,
            metadata={
                "canonical_content_scope": "parsed_semantics_and_hashes_only",
                "transport_content_archived": False,
            },
            _public_knowledge_execution_binding=binding,
        )
        if binding is None:
            return archive
        leakage_audits = [
            audit
            for execution in executions.values()
            for audit in execution.public_knowledge_audits
        ]
        return PublicKnowledgeExecutionArchive.create(
            binding=binding,
            archive=archive,
            transport_leakage_audits=leakage_audits,
        )

    def _preflight(self, plan, manifest, input_set):
        if not isinstance(plan, RealModelExperimentPlan):
            raise RealExperimentExecutionError(
                "execution requires RealModelExperimentPlan"
            )
        if not isinstance(manifest, BenchmarkManifest):
            raise RealExperimentExecutionError(
                "execution requires BenchmarkManifest"
            )
        if not isinstance(input_set, RealExperimentInputSet):
            raise RealExperimentExecutionError(
                "execution requires RealExperimentInputSet"
            )
        plan_snapshot = RealModelExperimentPlan.model_validate(
            plan.model_dump(mode="json")
        )
        if (
            plan_snapshot.execution_mode is ExperimentExecutionMode.REAL_PROVIDER
            and plan_snapshot.masked_prompt_projection_contract
            != PHASE10D_MASKED_PROMPT_PROJECTION_CONTRACT
        ):
            raise RealExperimentExecutionError(
                "REAL_PROVIDER requires current masked prompt projection contract"
            )
        if (
            plan_snapshot.execution_mode is ExperimentExecutionMode.REAL_PROVIDER
            and plan_snapshot.provider_descriptor.strict_json_schema
            and plan_snapshot.provider_descriptor.strict_schema_bundle_sha256
            is None
        ):
            raise RealExperimentExecutionError(
                "REAL_PROVIDER strict schema requires bundle provenance"
            )
        if (
            plan_snapshot.execution_mode is ExperimentExecutionMode.REAL_PROVIDER
            and plan_snapshot.provider_descriptor.api_style
            is LLMAPIStyle.RESPONSES
            and plan_snapshot.provider_descriptor.responses_completion_contract
            != PHASE10D_RESPONSES_COMPLETION_CONTRACT
        ):
            raise RealExperimentExecutionError(
                "REAL_PROVIDER Responses requires current completion contract"
            )
        manifest_snapshot = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json")
        )
        inputs = RealExperimentInputSet.model_validate(
            input_set.model_dump(mode="json")
        )
        if plan_snapshot.execution_mode is ExperimentExecutionMode.REAL_PROVIDER:
            incomplete_objective_inputs = [
                item.benchmark_case_id
                for item in inputs.case_inputs
                if item.triggerability is not None
                and item.objective_materialization is None
            ]
            if incomplete_objective_inputs:
                raise RealExperimentExecutionError(
                    "REAL_PROVIDER triggerability requires objective materialization"
                )
        if (
            manifest_snapshot.id,
            manifest_snapshot.benchmark_version,
        ) != (plan_snapshot.benchmark_manifest_id, plan_snapshot.benchmark_version):
            raise RealExperimentExecutionError("manifest and plan mismatch")
        manifest_cases = {item.id for item in manifest_snapshot.cases}
        input_cases = {item.benchmark_case_id for item in inputs.case_inputs}
        if manifest_cases != set(plan_snapshot.case_ids) or input_cases != set(
            plan_snapshot.case_ids
        ):
            raise RealExperimentExecutionError("execution case cohort mismatch")
        if inputs.experiment_plan_id != plan_snapshot.id:
            raise RealExperimentExecutionError("input set and plan mismatch")
        context_ids = [
            item.reasoning_context.id for item in inputs.case_inputs
        ]
        if len(context_ids) != len(set(context_ids)):
            raise RealExperimentExecutionError(
                "each benchmark case requires a distinct reasoning context"
            )
        cases = {item.id: item for item in manifest_snapshot.cases}
        for item in inputs.case_inputs:
            case = cases[item.benchmark_case_id]
            if item.reasoning_context.architecture is not case.architecture:
                raise RealExperimentExecutionError(
                    "reasoning context and case architecture mismatch"
                )
        if plan_snapshot.execution_mode is ExperimentExecutionMode.REAL_PROVIDER:
            if self._uses_custom_prompt_builder:
                raise RealExperimentExecutionError(
                    "REAL_PROVIDER requires the frozen prompt builder"
                )
            if not isinstance(
                self._provider, OpenAICompatibleReasoningProvider
            ):
                raise RealExperimentExecutionError(
                    "REAL_PROVIDER requires OpenAICompatibleReasoningProvider"
                )
            descriptor = RealModelProviderDescriptor.from_provider_config(
                self._provider.config
            )
            if descriptor.id != plan_snapshot.provider_descriptor.id:
                raise RealExperimentExecutionError(
                    "actual provider configuration does not match plan"
                )
        return plan_snapshot, manifest_snapshot, inputs

    @staticmethod
    def _ablation_plan(plan: RealModelExperimentPlan) -> AblationExperimentPlan:
        return AblationExperimentPlan(
            id=plan.ablation_plan_id,
            contract=PHASE10C_ABLATION_CONTRACT,
            benchmark_manifest_id=plan.benchmark_manifest_id,
            benchmark_version=plan.benchmark_version,
            condition_specs=plan.condition_specs,
            primary_model_condition=plan.ablation_primary_model_condition,
            metadata={},
        )

    def _execute_model_condition(
        self,
        plan,
        manifest,
        cases,
        inputs_by_case,
        *,
        condition,
        visibility,
        public_knowledge_binding=None,
    ) -> _ConditionExecution:
        execution = _ConditionExecution(condition=condition)
        pipeline_failed = False
        for case_id in plan.case_ids:
            case = cases[case_id]
            case_input = inputs_by_case[case_id]
            context = type(case_input.reasoning_context).model_validate(
                case_input.reasoning_context.model_dump(mode="json")
            )
            trace = _PerCaseInvocationTrace()
            hidden = (
                masked_chain_hidden_reference_ids(context)
                if condition
                is AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
                else None
            )
            public_case_binding = (
                public_knowledge_binding.case_binding(case_id)
                if public_knowledge_binding is not None
                else None
            )
            expected_records = (
                {
                    role: public_case_binding.expected_record(visibility, role)
                    for role in PHASE10D_PROVIDER_ROLE_ORDER
                }
                if public_case_binding is not None
                else None
            )
            engine = ReasoningEngine(
                provider=_RecordingReasoningProvider(self._provider, trace),
                prompt_builder=_RecordingPromptBuilder(
                    self._prompt_builder_factory(),
                    trace,
                    masked_hidden_reference_ids=hidden,
                    knowledge_projection=(
                        public_case_binding.knowledge_projection
                        if public_case_binding is not None
                        else None
                    ),
                    expected_prompt_sha256_by_role=(
                        {
                            role: record.expected_prompt_sha256
                            for role, record in expected_records.items()
                        }
                        if expected_records is not None
                        else None
                    ),
                    expected_leakage_audit_id_by_role=(
                        {
                            role: record.expected_leakage_audit_id
                            for role, record in expected_records.items()
                        }
                        if expected_records is not None
                        else None
                    ),
                    expected_visibility_audit_id_by_role=(
                        {
                            role: record.expected_visibility_audit_id
                            for role, record in expected_records.items()
                        }
                        if expected_records is not None
                        and visibility
                        is ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT
                        else None
                    ),
                ),
                parser=_RecordingReasoningParser(
                    ConstrainedReasoningOutputParser(), trace
                ),
                prompt_visibility=visibility,
            )
            workflow = ProviderBackedAgentWorkflow(engine=engine)
            session = None
            workflow_error = None
            try:
                session = workflow.execute(context)
            except ProviderBackedWorkflowExecutionError as error:
                workflow_error = error
            if workflow_error is not None and public_case_binding is not None:
                failed_attempt = trace.attempts.get(workflow_error.failed_role)
                if failed_attempt is not None and isinstance(
                    failed_attempt.error,
                    (_PromptVisibilityLeakError, _PublicKnowledgePromptGateError),
                ):
                    raise RealExperimentExecutionError(
                        "public prompt failed before transport"
                    ) from failed_attempt.error
            execution.invocation_records.extend(
                self._invocation_records_for_case(
                    plan,
                    condition,
                    case_id,
                    trace,
                    workflow_error,
                )
            )
            execution.audits.extend(
                item.audit
                for item in trace.attempts.values()
                if item.audit is not None
            )
            execution.public_knowledge_audits.extend(
                item.public_knowledge_audit
                for item in trace.attempts.values()
                if item.public_knowledge_audit is not None
            )
            if session is None:
                execution.case_runs.append(
                    self._failed_case_run(
                        plan,
                        condition,
                        case,
                        case_input,
                        stage=BenchmarkExecutionStage.REASONING_SESSION,
                        failure_code=(
                            BenchmarkExecutionFailureCode.PROVIDER_EXECUTION_FAILED
                        ),
                        session_binding=None,
                    )
                )
                continue
            session_binding = ExperimentCaseReasoningSession.create(
                plan,
                condition_kind=condition,
                benchmark_case_id=case_id,
                reasoning_session=session,
            )
            execution.sessions.append(session_binding)
            try:
                candidate = FinalizedCandidateBuilder.from_reasoning_session(
                    case.id, session
                )
            except Exception:
                pipeline_failed = True
                execution.case_runs.append(
                    self._failed_case_run(
                        plan,
                        condition,
                        case,
                        case_input,
                        stage=BenchmarkExecutionStage.CANDIDATE_FINALIZATION,
                        failure_code=(
                            BenchmarkExecutionFailureCode.CANDIDATE_FINALIZATION_FAILED
                        ),
                        session_binding=session_binding,
                    )
                )
                continue
            try:
                case_run = self._prepare_evaluation_case_run(
                    case, case_input, candidate
                )
            except Exception:
                pipeline_failed = True
                execution.case_runs.append(
                    self._failed_case_run(
                        plan,
                        condition,
                        case,
                        case_input,
                        stage=(
                            BenchmarkExecutionStage.EVALUATION_INPUT_PREPARATION
                        ),
                        failure_code=(
                            BenchmarkExecutionFailureCode.EVALUATION_INPUT_INVALID
                        ),
                        session_binding=session_binding,
                    )
                )
                continue
            execution.case_runs.append(
                ExperimentConditionCaseRun.create(
                    plan,
                    condition_kind=condition,
                    case_input=case_input,
                    case_run_record=case_run,
                    reasoning_session_binding=session_binding,
                )
            )

        invocation_failed = any(
            item.failure is not None or item.blocked_by_role is not None
            for item in execution.invocation_records
        )
        if invocation_failed or pipeline_failed:
            execution.failure = self._condition_failure(
                plan,
                condition,
                invocation_records=execution.invocation_records,
                pipeline_failed=pipeline_failed,
                audits=execution.audits,
            )
        else:
            try:
                execution.report = BenchmarkEvaluationRunner().evaluate(
                    manifest,
                    [item.case_run_record for item in execution.case_runs],
                )
            except Exception:
                execution.failure = AblationConditionExecutionFailure.create(
                    ablation_plan_id=plan.ablation_plan_id,
                    condition_kind=condition,
                    stage=AblationConditionFailureStage.REPORT_ASSEMBLY,
                    failure_code=AblationConditionFailureCode.REPORT_ASSEMBLY_FAILED,
                )
        return execution

    def _execute_no_model_condition(
        self, plan, manifest, cases, inputs_by_case
    ) -> _ConditionExecution:
        condition = AblationConditionKind.NO_MODEL_BASELINE
        execution = _ConditionExecution(condition=condition)
        failed = False
        for case_id in plan.case_ids:
            case = cases[case_id]
            case_input = inputs_by_case[case_id]
            session = None
            binding = None
            try:
                session = AgentWorkflow().execute(
                    case_input.reasoning_context
                )
            except Exception:
                failed = True
                execution.case_runs.append(
                    self._failed_case_run(
                        plan,
                        condition,
                        case,
                        case_input,
                        stage=BenchmarkExecutionStage.REASONING_SESSION,
                        failure_code=(
                            BenchmarkExecutionFailureCode.REASONING_CONTRACT_FAILED
                        ),
                        session_binding=None,
                    )
                )
                continue
            binding = ExperimentCaseReasoningSession.create(
                plan,
                condition_kind=condition,
                benchmark_case_id=case_id,
                reasoning_session=session,
            )
            execution.sessions.append(binding)
            try:
                candidate = FinalizedCandidateBuilder.from_reasoning_session(
                    case.id, session
                )
            except Exception:
                failed = True
                execution.case_runs.append(
                    self._failed_case_run(
                        plan,
                        condition,
                        case,
                        case_input,
                        stage=BenchmarkExecutionStage.CANDIDATE_FINALIZATION,
                        failure_code=(
                            BenchmarkExecutionFailureCode.CANDIDATE_FINALIZATION_FAILED
                        ),
                        session_binding=binding,
                    )
                )
                continue
            try:
                run = self._prepare_evaluation_case_run(
                    case, case_input, candidate
                )
            except Exception:
                failed = True
                execution.case_runs.append(
                    self._failed_case_run(
                        plan,
                        condition,
                        case,
                        case_input,
                        stage=(
                            BenchmarkExecutionStage.EVALUATION_INPUT_PREPARATION
                        ),
                        failure_code=(
                            BenchmarkExecutionFailureCode.EVALUATION_INPUT_INVALID
                        ),
                        session_binding=binding,
                    )
                )
                continue
            execution.case_runs.append(
                ExperimentConditionCaseRun.create(
                    plan,
                    condition_kind=condition,
                    case_input=case_input,
                    case_run_record=run,
                    reasoning_session_binding=binding,
                )
            )
        if failed:
            execution.failure = AblationConditionExecutionFailure.create(
                ablation_plan_id=plan.ablation_plan_id,
                condition_kind=condition,
                stage=AblationConditionFailureStage.ORCHESTRATION,
                failure_code=(
                    AblationConditionFailureCode.CONDITION_ORCHESTRATION_FAILED
                ),
            )
        else:
            try:
                execution.report = BenchmarkEvaluationRunner().evaluate(
                    manifest,
                    [item.case_run_record for item in execution.case_runs],
                )
            except Exception:
                execution.failure = AblationConditionExecutionFailure.create(
                    ablation_plan_id=plan.ablation_plan_id,
                    condition_kind=condition,
                    stage=AblationConditionFailureStage.REPORT_ASSEMBLY,
                    failure_code=(
                        AblationConditionFailureCode.REPORT_ASSEMBLY_FAILED
                    ),
                )
        return execution

    @staticmethod
    def _execute_upper_condition(
        plan, manifest, no_model: _ConditionExecution
    ) -> _ConditionExecution:
        condition = AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND
        execution = _ConditionExecution(condition=condition)
        if no_model.failure is not None:
            execution.failure = AblationConditionExecutionFailure.create(
                ablation_plan_id=plan.ablation_plan_id,
                condition_kind=condition,
                stage=AblationConditionFailureStage.REPORT_ASSEMBLY,
                failure_code=AblationConditionFailureCode.REPORT_ASSEMBLY_FAILED,
            )
            return execution
        try:
            execution.report = ContextObjectiveUpperBoundEvaluator().evaluate(
                manifest,
                [item.case_run_record for item in no_model.case_runs],
            )
        except Exception:
            execution.failure = AblationConditionExecutionFailure.create(
                ablation_plan_id=plan.ablation_plan_id,
                condition_kind=condition,
                stage=AblationConditionFailureStage.REPORT_ASSEMBLY,
                failure_code=AblationConditionFailureCode.REPORT_ASSEMBLY_FAILED,
            )
        return execution

    @staticmethod
    def _prepare_evaluation_case_run(case, case_input, candidate):
        interaction = case_input.reasoning_context.cross_layer_interaction
        binding = ModelClaimBinder().assess(
            candidate, candidate_interaction=interaction
        )
        feasibility = ChainFeasibilityOracle().assess(
            candidate,
            case.artifact,
            candidate_interaction=interaction,
            triggerability=case_input.triggerability,
        )
        bundle = CandidateEvaluationBundle.create(
            candidate=candidate,
            claim_binding=binding,
            feasibility=feasibility,
            triggerability=case_input.triggerability,
        )
        return BenchmarkCaseRunRecord.from_candidate(bundle)

    @staticmethod
    def _failed_case_run(
        plan,
        condition,
        case: EvaluationBenchmarkCase,
        case_input,
        *,
        stage,
        failure_code,
        session_binding,
    ) -> ExperimentConditionCaseRun:
        failure = BenchmarkCaseExecutionFailure.create(
            benchmark_case_id=case.id,
            architecture=case.architecture,
            stage=stage,
            failure_code=failure_code,
            metadata={"phase10d_step2_bounded_failure": True},
        )
        run = BenchmarkCaseRunRecord.from_execution_failure(failure)
        return ExperimentConditionCaseRun.create(
            plan,
            condition_kind=condition,
            case_input=case_input,
            case_run_record=run,
            reasoning_session_binding=session_binding,
        )

    @staticmethod
    def _invocation_records_for_case(
        plan, condition, case_id, trace, workflow_error
    ) -> list[ModelInvocationRecord]:
        failed_role = (
            workflow_error.failed_role if workflow_error is not None else None
        )
        records = []
        for role in PHASE10D_PROVIDER_ROLE_ORDER:
            key = ExperimentCaseInvocationKey.create(
                plan,
                condition_kind=condition,
                benchmark_case_id=case_id,
                role=role,
            )
            attempt = trace.attempts.get(role)
            if failed_role is None:
                if attempt is None or not attempt.parse_completed:
                    raise RuntimeError("completed workflow lost invocation trace")
                records.append(
                    ModelInvocationRecord.completed(
                        plan,
                        key,
                        prompt=attempt.prompt,
                        raw_provider_response=attempt.raw_response,
                    )
                )
            elif role is failed_role:
                stage, code, parser_detail, provider_detail = (
                    RealModelExperimentExecutor._map_failure(attempt)
                )
                bounded = RealModelInvocationFailure.create(
                    key,
                    stage=stage,
                    failure_code=code,
                    parser_failure_detail=parser_detail,
                    provider_response_failure_detail=provider_detail,
                )
                records.append(
                    ModelInvocationRecord.failed(
                        plan,
                        key,
                        failure=bounded,
                        prompt=attempt.prompt if attempt is not None else None,
                        raw_provider_response=(
                            attempt.raw_response if attempt is not None else None
                        ),
                    )
                )
            elif PHASE10D_PROVIDER_ROLE_ORDER.index(role) < (
                PHASE10D_PROVIDER_ROLE_ORDER.index(failed_role)
            ):
                if attempt is None or not attempt.parse_completed:
                    raise RuntimeError("completed earlier role lost trace")
                records.append(
                    ModelInvocationRecord.completed(
                        plan,
                        key,
                        prompt=attempt.prompt,
                        raw_provider_response=attempt.raw_response,
                    )
                )
            else:
                records.append(
                    ModelInvocationRecord.not_attempted(
                        plan, key, blocked_by_role=failed_role
                    )
                )
        return records

    @staticmethod
    def _map_failure(attempt):
        if attempt is None or attempt.prompt is None:
            return (
                RealModelInvocationFailureStage.PROMPT_CONSTRUCTION,
                RealModelInvocationFailureCode.OTHER_BOUNDED_FAILURE,
                None,
                None,
            )
        error = attempt.error
        if isinstance(error, _PromptVisibilityLeakError):
            return (
                RealModelInvocationFailureStage.PROMPT_CONSTRUCTION,
                RealModelInvocationFailureCode.PROMPT_VISIBILITY_FAILED,
                None,
                None,
            )
        if attempt.parse_completed:
            return (
                RealModelInvocationFailureStage.WORKFLOW_ASSEMBLY,
                RealModelInvocationFailureCode.WORKFLOW_CONTRACT_FAILED,
                None,
                None,
            )
        if attempt.parse_entered:
            if isinstance(error, LLMOutputValidationError) and (
                error.stage == "response_content"
            ):
                return (
                    RealModelInvocationFailureStage.PROVIDER_RESPONSE,
                    RealModelInvocationFailureCode.PROVIDER_RESPONSE_INVALID,
                    None,
                    None,
                )
            return (
                RealModelInvocationFailureStage.STRUCTURED_PARSE,
                RealModelInvocationFailureCode.PROVIDER_CONTRACT_REJECTED,
                RealModelExperimentExecutor._parse_failure_detail(error),
                None,
            )
        if isinstance(error, LLMProviderConfigurationError):
            return (
                RealModelInvocationFailureStage.PROVIDER_CONNECTION,
                RealModelInvocationFailureCode.PROVIDER_UNAVAILABLE,
                None,
                None,
            )
        if isinstance(error, TimeoutError):
            return (
                RealModelInvocationFailureStage.PROVIDER_TRANSPORT,
                RealModelInvocationFailureCode.PROVIDER_TIMEOUT,
                None,
                None,
            )
        if isinstance(error, LLMProviderResponseError):
            if error.stage == "response_incomplete":
                return (
                    RealModelInvocationFailureStage.PROVIDER_RESPONSE,
                    RealModelInvocationFailureCode.PROVIDER_RESPONSE_INVALID,
                    None,
                    RealModelExperimentExecutor._provider_response_detail(
                        error
                    ),
                )
            if error.stage == "response_failed":
                return (
                    RealModelInvocationFailureStage.PROVIDER_RESPONSE,
                    RealModelInvocationFailureCode.PROVIDER_RESPONSE_INVALID,
                    None,
                    ProviderResponseFailureDetail.PROVIDER_REPORTED_FAILED,
                )
            if error.stage == "response_nonterminal":
                return (
                    RealModelInvocationFailureStage.PROVIDER_RESPONSE,
                    RealModelInvocationFailureCode.PROVIDER_RESPONSE_INVALID,
                    None,
                    (
                        ProviderResponseFailureDetail.
                        NONTERMINAL_OR_UNKNOWN_STATUS
                    ),
                )
            if error.stage == "connection":
                return (
                    RealModelInvocationFailureStage.PROVIDER_CONNECTION,
                    RealModelInvocationFailureCode.PROVIDER_UNAVAILABLE,
                    None,
                    None,
                )
            if error.stage == "transport":
                code = (
                    RealModelInvocationFailureCode.PROVIDER_TIMEOUT
                    if error.status_code in {408, 504}
                    else RealModelInvocationFailureCode.OTHER_BOUNDED_FAILURE
                )
                return (
                    RealModelInvocationFailureStage.PROVIDER_TRANSPORT,
                    code,
                    None,
                    None,
                )
            return (
                RealModelInvocationFailureStage.PROVIDER_RESPONSE,
                RealModelInvocationFailureCode.PROVIDER_RESPONSE_INVALID,
                None,
                None,
            )
        return (
            RealModelInvocationFailureStage.PROVIDER_TRANSPORT,
            RealModelInvocationFailureCode.OTHER_BOUNDED_FAILURE,
            None,
            None,
        )

    @staticmethod
    def _provider_response_detail(
        error: LLMProviderResponseError,
    ) -> ProviderResponseFailureDetail:
        return {
            ProviderIncompleteReason.MAX_OUTPUT_TOKENS: (
                ProviderResponseFailureDetail.MAX_OUTPUT_TOKENS
            ),
            ProviderIncompleteReason.CONTENT_FILTER: (
                ProviderResponseFailureDetail.CONTENT_FILTER
            ),
        }.get(
            error.completion_reason,
            (
                ProviderResponseFailureDetail.
                OTHER_BOUNDED_PROVIDER_RESPONSE_FAILURE
            ),
        )

    @staticmethod
    def _parse_failure_detail(error) -> StructuredParseFailureDetail:
        if not isinstance(error, LLMOutputValidationError):
            return StructuredParseFailureDetail.OTHER_BOUNDED_PARSE_FAILURE
        return {
            "json_parse": StructuredParseFailureDetail.JSON_PARSE,
            "output_schema": StructuredParseFailureDetail.OUTPUT_SCHEMA,
            "forbidden_truth_field": (
                StructuredParseFailureDetail.FORBIDDEN_TRUTH_FIELD
            ),
            "role_authority": StructuredParseFailureDetail.ROLE_AUTHORITY,
            "request_cardinality": (
                StructuredParseFailureDetail.REQUEST_CARDINALITY
            ),
            "evidence_reference": (
                StructuredParseFailureDetail.EVIDENCE_REFERENCE
            ),
        }.get(
            error.stage,
            StructuredParseFailureDetail.OTHER_BOUNDED_PARSE_FAILURE,
        )

    @staticmethod
    def _condition_failure(
        plan,
        condition,
        *,
        invocation_records,
        pipeline_failed,
        audits,
    ):
        leaked = any(
            item.status is PromptVisibilityAuditStatus.LEAK_DETECTED
            for item in audits
        )
        if leaked:
            stage = AblationConditionFailureStage.PROMPT_VISIBILITY
            code = (
                AblationConditionFailureCode.PROMPT_VISIBILITY_CONSTRUCTION_FAILED
            )
        elif any(
            item.failure is not None
            and item.failure.stage
            in {
                RealModelInvocationFailureStage.PROVIDER_CONNECTION,
                RealModelInvocationFailureStage.PROVIDER_TRANSPORT,
            }
            for item in invocation_records
        ):
            stage = AblationConditionFailureStage.PROVIDER
            code = AblationConditionFailureCode.PROVIDER_UNAVAILABLE
        elif pipeline_failed:
            stage = AblationConditionFailureStage.ORCHESTRATION
            code = AblationConditionFailureCode.CONDITION_ORCHESTRATION_FAILED
        else:
            # Structured-response and workflow failures remain orchestration
            # failures rather than being mislabeled provider unavailability.
            stage = AblationConditionFailureStage.ORCHESTRATION
            code = AblationConditionFailureCode.CONDITION_ORCHESTRATION_FAILED
        return AblationConditionExecutionFailure.create(
            ablation_plan_id=plan.ablation_plan_id,
            condition_kind=condition,
            stage=stage,
            failure_code=code,
        )

    @staticmethod
    def _condition_result(plan, execution):
        kwargs = {
            "ablation_plan_id": plan.ablation_plan_id,
            "condition_kind": execution.condition,
            "benchmark_manifest_id": plan.benchmark_manifest_id,
            "prompt_visibility_audit_ids": [
                item.id for item in execution.audits
            ],
        }
        if execution.failure is not None:
            kwargs["execution_failure"] = execution.failure
        elif (
            execution.condition
            is AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND
        ):
            kwargs["context_objective_upper_bound_result"] = execution.report
        else:
            kwargs["benchmark_evaluation_report"] = execution.report
        return AblationConditionResult.create(**kwargs)

    @staticmethod
    def _condition_record(plan, execution):
        kwargs = {
            "condition_kind": execution.condition,
            "invocation_records": execution.invocation_records,
            "prompt_visibility_audits": execution.audits,
            "condition_failure": execution.failure,
        }
        if execution.failure is None and (
            execution.condition
            is AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND
        ):
            kwargs["context_objective_upper_bound_result"] = execution.report
        elif execution.failure is None:
            kwargs["benchmark_evaluation_report"] = execution.report
        return RealExperimentConditionRecord.create(plan, **kwargs)
