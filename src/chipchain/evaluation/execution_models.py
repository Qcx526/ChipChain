"""Phase 10D Step 2 detached execution inputs and canonical archive."""

from __future__ import annotations

from pydantic import Field, field_validator, model_validator

from chipchain.agents.base import ReasoningContext
from chipchain.agents.state import ReasoningSession
from chipchain.evaluation.ablation import ContextObjectiveUpperBoundEvaluator
from chipchain.evaluation.benchmark_models import BenchmarkCaseRunRecord
from chipchain.evaluation.enums import (
    AblationConditionKind,
    BenchmarkCaseRunDisposition,
)
from chipchain.evaluation.experiment_artifact import RealModelExperimentArtifact
from chipchain.evaluation.experiment_models import (
    RealModelExperimentPlan,
    _validate_experiment_metadata,
)
from chipchain.evaluation.models import BenchmarkManifest, _canonical_hash
from chipchain.hardware_trigger.aggregation import TriggerabilityAggregationResult
from chipchain.models.common import DomainModel, Identifier, Metadata


PHASE10D_EXECUTION_CONTRACT = "phase10d_real_model_execution_v1"
_SESSION_CONDITIONS = frozenset(
    {
        AblationConditionKind.FULL_CONTEXT_MODEL,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        AblationConditionKind.NO_MODEL_BASELINE,
    }
)


def _validate_case_input_metadata(value: Metadata) -> Metadata:
    """Reject transport state and Ground Truth smuggling through metadata."""

    _validate_experiment_metadata(value)

    def visit(item: object) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                normalized = "".join(
                    character
                    for character in str(key).lower()
                    if character.isalnum()
                )
                if "groundtruth" in normalized:
                    raise ValueError(
                        "candidate-side input metadata cannot contain Ground Truth"
                    )
                visit(nested)
        elif isinstance(item, list):
            for nested in item:
                visit(nested)

    visit(value)
    return value


def real_experiment_case_input_id(
    *,
    experiment_plan_id: str,
    benchmark_case_id: str,
    reasoning_context_id: str,
    triggerability_aggregation_id: str | None,
) -> str:
    """Bind one case input without metadata, Ground Truth, or host state."""

    return _canonical_hash(
        "real-experiment-case-input",
        {
            "benchmark_case_id": benchmark_case_id,
            "experiment_plan_id": experiment_plan_id,
            "reasoning_context_id": reasoning_context_id,
            "triggerability_aggregation_id": triggerability_aggregation_id,
        },
    )


class RealExperimentCaseInput(DomainModel):
    """Detached candidate-side input for one planned benchmark case."""

    id: Identifier
    experiment_plan_id: Identifier
    benchmark_case_id: Identifier
    reasoning_context: ReasoningContext
    triggerability: TriggerabilityAggregationResult | None = None
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("reasoning_context")
    @classmethod
    def snapshot_context(cls, value: ReasoningContext) -> ReasoningContext:
        return ReasoningContext.model_validate(value.model_dump(mode="json"))

    @field_validator("triggerability")
    @classmethod
    def snapshot_triggerability(
        cls, value: TriggerabilityAggregationResult | None
    ) -> TriggerabilityAggregationResult | None:
        if value is None:
            return None
        return TriggerabilityAggregationResult.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_case_input_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "RealExperimentCaseInput":
        expected = real_experiment_case_input_id(
            experiment_plan_id=self.experiment_plan_id,
            benchmark_case_id=self.benchmark_case_id,
            reasoning_context_id=self.reasoning_context.id,
            triggerability_aggregation_id=(
                self.triggerability.id if self.triggerability is not None else None
            ),
        )
        if self.id != expected:
            raise ValueError("RealExperimentCaseInput ID is not deterministic")
        if (
            self.triggerability is not None
            and self.triggerability.architecture
            is not self.reasoning_context.architecture
        ):
            raise ValueError("case input triggerability architecture mismatch")
        return self

    @classmethod
    def create(
        cls,
        plan: RealModelExperimentPlan,
        *,
        benchmark_case_id: str,
        reasoning_context: ReasoningContext,
        triggerability: TriggerabilityAggregationResult | None = None,
        metadata: Metadata | None = None,
    ) -> "RealExperimentCaseInput":
        """Create an input only for a case frozen in ``plan``."""

        if not isinstance(plan, RealModelExperimentPlan):
            raise TypeError("case input requires RealModelExperimentPlan")
        case_id = benchmark_case_id.strip()
        if case_id not in plan.case_ids:
            raise ValueError("case input is outside frozen experiment plan")
        context = ReasoningContext.model_validate(
            reasoning_context.model_dump(mode="json")
        )
        trigger = (
            TriggerabilityAggregationResult.model_validate(
                triggerability.model_dump(mode="json")
            )
            if triggerability is not None
            else None
        )
        values = {
            "experiment_plan_id": plan.id,
            "benchmark_case_id": case_id,
            "reasoning_context_id": context.id,
            "triggerability_aggregation_id": (
                trigger.id if trigger is not None else None
            ),
        }
        return cls(
            id=real_experiment_case_input_id(**values),
            experiment_plan_id=plan.id,
            benchmark_case_id=case_id,
            reasoning_context=context,
            triggerability=trigger,
            metadata=metadata or {},
        )


def real_experiment_input_set_id(
    *, experiment_plan_id: str, case_input_ids: list[str]
) -> str:
    """Build ordering-neutral identity for one exact candidate-side cohort."""

    return _canonical_hash(
        "real-experiment-input-set",
        {
            "case_input_ids": sorted(case_input_ids),
            "experiment_plan_id": experiment_plan_id,
        },
    )


class RealExperimentInputSet(DomainModel):
    """Exactly one detached candidate-side input for every planned case."""

    id: Identifier
    experiment_plan_id: Identifier
    case_inputs: list[RealExperimentCaseInput] = Field(min_length=1)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("case_inputs")
    @classmethod
    def normalize_inputs(
        cls, values: list[RealExperimentCaseInput]
    ) -> list[RealExperimentCaseInput]:
        if len(values) != len({item.id for item in values}):
            raise ValueError("input-set case input IDs must be unique")
        if len(values) != len({item.benchmark_case_id for item in values}):
            raise ValueError("input set permits exactly one input per case")
        return sorted(values, key=lambda item: item.benchmark_case_id)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_case_input_metadata(value)

    @model_validator(mode="after")
    def validate_bindings_and_identity(self) -> "RealExperimentInputSet":
        if any(
            item.experiment_plan_id != self.experiment_plan_id
            for item in self.case_inputs
        ):
            raise ValueError("input-set case belongs to another experiment plan")
        expected = real_experiment_input_set_id(
            experiment_plan_id=self.experiment_plan_id,
            case_input_ids=[item.id for item in self.case_inputs],
        )
        if self.id != expected:
            raise ValueError("RealExperimentInputSet ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        plan: RealModelExperimentPlan,
        *,
        case_inputs: list[RealExperimentCaseInput],
        metadata: Metadata | None = None,
    ) -> "RealExperimentInputSet":
        """Freeze the exact plan cohort, rejecting missing and extra cases."""

        if not isinstance(plan, RealModelExperimentPlan):
            raise TypeError("input set requires RealModelExperimentPlan")
        snapshots = [
            RealExperimentCaseInput.model_validate(item.model_dump(mode="json"))
            for item in case_inputs
        ]
        if {item.benchmark_case_id for item in snapshots} != set(plan.case_ids):
            raise ValueError("input-set cases must exactly match experiment plan")
        if any(item.experiment_plan_id != plan.id for item in snapshots):
            raise ValueError("input set contains input from another plan")
        return cls(
            id=real_experiment_input_set_id(
                experiment_plan_id=plan.id,
                case_input_ids=[item.id for item in snapshots],
            ),
            experiment_plan_id=plan.id,
            case_inputs=snapshots,
            metadata=metadata or {},
        )


def experiment_case_reasoning_session_id(
    *,
    experiment_plan_id: str,
    condition_kind: AblationConditionKind,
    benchmark_case_id: str,
    reasoning_session_id: str,
    reasoning_session_output_binding_id: str,
) -> str:
    return _canonical_hash(
        "experiment-case-reasoning-session",
        {
            "benchmark_case_id": benchmark_case_id,
            "condition_kind": AblationConditionKind(condition_kind).value,
            "experiment_plan_id": experiment_plan_id,
            "reasoning_session_id": reasoning_session_id,
            "reasoning_session_output_binding_id": (
                reasoning_session_output_binding_id
            ),
        },
    )


def reasoning_session_output_binding_id(session: ReasoningSession) -> str:
    """Bind parsed contract identities absent from output-neutral session ID."""

    return _canonical_hash(
        "reasoning-session-output-binding",
        {
            "evidence_request_ids": [
                item.id for item in session.evidence_requests
            ],
            "feedback_ids": [item.id for item in session.feedbacks],
            "final_reasoning_result_id": session.final_reasoning_result.id,
            "hypothesis_ids": [item.id for item in session.hypotheses],
            "merged_hypothesis_id": session.merged_hypothesis.id,
            "message_ids": [item.id for item in session.messages],
            "reasoning_result_ids": [
                item.id for item in session.reasoning_results
            ],
            "session_id": session.session_id,
        },
    )


class ExperimentCaseReasoningSession(DomainModel):
    """Typed condition/case binding for one parsed successful session."""

    id: Identifier
    experiment_plan_id: Identifier
    condition_kind: AblationConditionKind
    benchmark_case_id: Identifier
    reasoning_session: ReasoningSession

    @model_validator(mode="after")
    def validate_binding_and_identity(self) -> "ExperimentCaseReasoningSession":
        if self.condition_kind not in _SESSION_CONDITIONS:
            raise ValueError("upper-bound condition does not create a session")
        expected = experiment_case_reasoning_session_id(
            experiment_plan_id=self.experiment_plan_id,
            condition_kind=self.condition_kind,
            benchmark_case_id=self.benchmark_case_id,
            reasoning_session_id=self.reasoning_session.session_id,
            reasoning_session_output_binding_id=(
                reasoning_session_output_binding_id(self.reasoning_session)
            ),
        )
        if self.id != expected:
            raise ValueError("case reasoning session ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        plan: RealModelExperimentPlan,
        *,
        condition_kind: AblationConditionKind | str,
        benchmark_case_id: str,
        reasoning_session: ReasoningSession,
    ) -> "ExperimentCaseReasoningSession":
        condition = AblationConditionKind(condition_kind)
        case_id = benchmark_case_id.strip()
        if case_id not in plan.case_ids:
            raise ValueError("session case is outside experiment plan")
        session = ReasoningSession.model_validate(
            reasoning_session.model_dump(mode="json")
        )
        values = {
            "experiment_plan_id": plan.id,
            "condition_kind": condition,
            "benchmark_case_id": case_id,
            "reasoning_session_id": session.session_id,
            "reasoning_session_output_binding_id": (
                reasoning_session_output_binding_id(session)
            ),
        }
        return cls(
            id=experiment_case_reasoning_session_id(**values),
            experiment_plan_id=plan.id,
            condition_kind=condition,
            benchmark_case_id=case_id,
            reasoning_session=session,
        )


def experiment_condition_case_run_id(
    *,
    experiment_plan_id: str,
    condition_kind: AblationConditionKind,
    benchmark_case_id: str,
    benchmark_case_run_record_id: str,
    reasoning_session_binding_id: str | None,
) -> str:
    return _canonical_hash(
        "experiment-condition-case-run",
        {
            "benchmark_case_id": benchmark_case_id,
            "benchmark_case_run_record_id": benchmark_case_run_record_id,
            "condition_kind": AblationConditionKind(condition_kind).value,
            "experiment_plan_id": experiment_plan_id,
            "reasoning_session_binding_id": reasoning_session_binding_id,
        },
    )


class ExperimentConditionCaseRun(DomainModel):
    """Typed condition/case wrapper around an exact Phase 10B run record."""

    id: Identifier
    experiment_plan_id: Identifier
    condition_kind: AblationConditionKind
    benchmark_case_id: Identifier
    case_run_record: BenchmarkCaseRunRecord
    reasoning_session_binding_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_binding_and_identity(self) -> "ExperimentConditionCaseRun":
        if self.condition_kind not in _SESSION_CONDITIONS:
            raise ValueError("upper-bound condition reuses NO_MODEL case runs")
        if self.case_run_record.benchmark_case_id != self.benchmark_case_id:
            raise ValueError("archived case-run benchmark case mismatch")
        if (
            self.case_run_record.disposition
            is BenchmarkCaseRunDisposition.CANDIDATE
            and self.reasoning_session_binding_id is None
        ):
            raise ValueError("candidate case run requires a session binding")
        expected = experiment_condition_case_run_id(
            experiment_plan_id=self.experiment_plan_id,
            condition_kind=self.condition_kind,
            benchmark_case_id=self.benchmark_case_id,
            benchmark_case_run_record_id=self.case_run_record.id,
            reasoning_session_binding_id=self.reasoning_session_binding_id,
        )
        if self.id != expected:
            raise ValueError("condition case-run ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        plan: RealModelExperimentPlan,
        *,
        condition_kind: AblationConditionKind | str,
        case_run_record: BenchmarkCaseRunRecord,
        reasoning_session_binding: ExperimentCaseReasoningSession | None,
    ) -> "ExperimentConditionCaseRun":
        condition = AblationConditionKind(condition_kind)
        run = BenchmarkCaseRunRecord.model_validate(
            case_run_record.model_dump(mode="json")
        )
        binding_id = (
            reasoning_session_binding.id
            if reasoning_session_binding is not None
            else None
        )
        if reasoning_session_binding is not None and (
            reasoning_session_binding.experiment_plan_id,
            reasoning_session_binding.condition_kind,
            reasoning_session_binding.benchmark_case_id,
        ) != (plan.id, condition, run.benchmark_case_id):
            raise ValueError("case-run session binding mismatch")
        values = {
            "experiment_plan_id": plan.id,
            "condition_kind": condition,
            "benchmark_case_id": run.benchmark_case_id,
            "benchmark_case_run_record_id": run.id,
            "reasoning_session_binding_id": binding_id,
        }
        return cls(
            id=experiment_condition_case_run_id(**values),
            experiment_plan_id=plan.id,
            condition_kind=condition,
            benchmark_case_id=run.benchmark_case_id,
            case_run_record=run,
            reasoning_session_binding_id=binding_id,
        )


def real_model_execution_archive_id(
    *,
    contract: str,
    experiment_plan_id: str,
    benchmark_manifest_id: str,
    input_set_id: str,
    experiment_artifact_id: str,
    reasoning_session_binding_ids: list[str],
    archived_case_run_binding_ids: list[str],
) -> str:
    """Bind Step 2 inputs/outputs while excluding metadata and runtime state."""

    return _canonical_hash(
        "real-model-execution-archive",
        {
            "archived_case_run_binding_ids": sorted(
                archived_case_run_binding_ids
            ),
            "benchmark_manifest_id": benchmark_manifest_id,
            "contract": contract,
            "experiment_artifact_id": experiment_artifact_id,
            "experiment_plan_id": experiment_plan_id,
            "input_set_id": input_set_id,
            "reasoning_session_binding_ids": sorted(
                reasoning_session_binding_ids
            ),
        },
    )


class RealModelExecutionArchive(DomainModel):
    """Canonical Step 2 envelope for exact inputs and parsed semantic outputs."""

    id: Identifier
    contract: Identifier
    experiment_plan_id: Identifier
    benchmark_manifest: BenchmarkManifest
    input_set: RealExperimentInputSet
    experiment_artifact: RealModelExperimentArtifact
    reasoning_sessions: list[ExperimentCaseReasoningSession]
    case_run_records_by_condition: list[ExperimentConditionCaseRun]
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("benchmark_manifest")
    @classmethod
    def snapshot_manifest(cls, value: BenchmarkManifest) -> BenchmarkManifest:
        return BenchmarkManifest.model_validate(value.model_dump(mode="json"))

    @field_validator("input_set")
    @classmethod
    def snapshot_input_set(
        cls, value: RealExperimentInputSet
    ) -> RealExperimentInputSet:
        return RealExperimentInputSet.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("experiment_artifact")
    @classmethod
    def snapshot_experiment_artifact(
        cls, value: RealModelExperimentArtifact
    ) -> RealModelExperimentArtifact:
        return RealModelExperimentArtifact.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("reasoning_sessions")
    @classmethod
    def normalize_sessions(
        cls, values: list[ExperimentCaseReasoningSession]
    ) -> list[ExperimentCaseReasoningSession]:
        values = [
            ExperimentCaseReasoningSession.model_validate(
                item.model_dump(mode="json")
            )
            for item in values
        ]
        keys = [(item.condition_kind, item.benchmark_case_id) for item in values]
        if len(keys) != len(set(keys)) or len(values) != len({item.id for item in values}):
            raise ValueError("archive session bindings must be unique")
        return sorted(
            values,
            key=lambda item: (item.condition_kind.value, item.benchmark_case_id),
        )

    @field_validator("case_run_records_by_condition")
    @classmethod
    def normalize_case_runs(
        cls, values: list[ExperimentConditionCaseRun]
    ) -> list[ExperimentConditionCaseRun]:
        values = [
            ExperimentConditionCaseRun.model_validate(
                item.model_dump(mode="json")
            )
            for item in values
        ]
        keys = [(item.condition_kind, item.benchmark_case_id) for item in values]
        if len(keys) != len(set(keys)) or len(values) != len({item.id for item in values}):
            raise ValueError("archive condition case-run bindings must be unique")
        return sorted(
            values,
            key=lambda item: (item.condition_kind.value, item.benchmark_case_id),
        )

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_experiment_metadata(value)

    @model_validator(mode="after")
    def validate_cross_bindings_and_identity(self) -> "RealModelExecutionArchive":
        if self.contract != PHASE10D_EXECUTION_CONTRACT:
            raise ValueError("unsupported Phase 10D execution archive contract")
        self._validate_nested_metadata()
        plan = self.experiment_artifact.experiment_plan
        if self.experiment_plan_id != plan.id:
            raise ValueError("archive and nested experiment plan mismatch")
        if self.input_set.experiment_plan_id != plan.id:
            raise ValueError("archive input set belongs to another plan")
        if (
            self.benchmark_manifest.id,
            self.benchmark_manifest.benchmark_version,
        ) != (plan.benchmark_manifest_id, plan.benchmark_version):
            raise ValueError("archive benchmark manifest mismatch")
        manifest_case_ids = {item.id for item in self.benchmark_manifest.cases}
        if manifest_case_ids != set(plan.case_ids) or manifest_case_ids != {
            item.benchmark_case_id for item in self.input_set.case_inputs
        }:
            raise ValueError("archive case cohort mismatch")

        input_by_case = {
            item.benchmark_case_id: item for item in self.input_set.case_inputs
        }
        session_by_id = {item.id: item for item in self.reasoning_sessions}
        expected_run_keys = {
            (condition, case_id)
            for condition in _SESSION_CONDITIONS
            for case_id in plan.case_ids
        }
        run_by_key = {
            (item.condition_kind, item.benchmark_case_id): item
            for item in self.case_run_records_by_condition
        }
        if set(run_by_key) != expected_run_keys:
            raise ValueError("archive requires FULL/MASKED/NO_MODEL run accounting")
        for binding in self.reasoning_sessions:
            if (
                binding.experiment_plan_id != plan.id
                or binding.benchmark_case_id not in plan.case_ids
            ):
                raise ValueError("archive session is outside the experiment plan")
            case_input = input_by_case.get(binding.benchmark_case_id)
            if case_input is None or (
                binding.reasoning_session.reasoning_context.id
                != case_input.reasoning_context.id
            ):
                raise ValueError(
                    "archive session reasoning context does not match case input"
                )
        for wrapped in self.case_run_records_by_condition:
            if wrapped.experiment_plan_id != plan.id:
                raise ValueError("archive case run belongs to another plan")
            session = (
                session_by_id.get(wrapped.reasoning_session_binding_id)
                if wrapped.reasoning_session_binding_id is not None
                else None
            )
            if wrapped.reasoning_session_binding_id is not None and session is None:
                raise ValueError("archive case run references missing session")
            if session is not None and (
                session.condition_kind,
                session.benchmark_case_id,
            ) != (wrapped.condition_kind, wrapped.benchmark_case_id):
                raise ValueError("archive case run cross-wires a session")
            bundle = wrapped.case_run_record.candidate_bundle
            if bundle is not None:
                if session is None:
                    raise ValueError("candidate case run and session mismatch")
                candidate = bundle.candidate
                archived_session = session.reasoning_session
                if (
                    candidate.reasoning_session_id,
                    candidate.reasoning_context_id,
                    candidate.workflow_contract,
                    candidate.merged_hypothesis_id,
                ) != (
                    archived_session.session_id,
                    archived_session.reasoning_context.id,
                    archived_session.workflow_contract,
                    archived_session.merged_hypothesis.id,
                ):
                    raise ValueError("candidate case run and session mismatch")
        referenced_session_ids = {
            item.reasoning_session_binding_id
            for item in self.case_run_records_by_condition
            if item.reasoning_session_binding_id is not None
        }
        if referenced_session_ids != set(session_by_id):
            raise ValueError("archive contains an unbound reasoning session")

        condition_records = {
            item.condition_kind: item
            for item in self.experiment_artifact.condition_records
        }
        for condition in (
            AblationConditionKind.FULL_CONTEXT_MODEL,
            AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
            AblationConditionKind.NO_MODEL_BASELINE,
        ):
            report = condition_records[condition].benchmark_evaluation_report
            archived_runs = [
                run_by_key[(condition, case_id)].case_run_record
                for case_id in plan.case_ids
            ]
            if report is not None and set(report.case_run_record_ids) != {
                item.id for item in archived_runs
            }:
                raise ValueError("condition report and archived case runs mismatch")

        upper = condition_records[
            AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND
        ].context_objective_upper_bound_result
        if upper is not None:
            no_model_runs = [
                run_by_key[
                    (AblationConditionKind.NO_MODEL_BASELINE, case_id)
                ].case_run_record
                for case_id in plan.case_ids
            ]
            derived = ContextObjectiveUpperBoundEvaluator().evaluate(
                self.benchmark_manifest, no_model_runs
            )
            if derived.id != upper.id:
                raise ValueError("upper bound does not derive from NO_MODEL cohort")

        expected = real_model_execution_archive_id(
            contract=self.contract,
            experiment_plan_id=self.experiment_plan_id,
            benchmark_manifest_id=self.benchmark_manifest.id,
            input_set_id=self.input_set.id,
            experiment_artifact_id=self.experiment_artifact.id,
            reasoning_session_binding_ids=[
                item.id for item in self.reasoning_sessions
            ],
            archived_case_run_binding_ids=[
                item.id for item in self.case_run_records_by_condition
            ],
        )
        if self.id != expected:
            raise ValueError("RealModelExecutionArchive ID is not deterministic")
        return self

    def _validate_nested_metadata(self) -> None:
        """Prevent nested execution inputs/outputs from carrying transport state."""

        def visit(value: object) -> None:
            if isinstance(value, DomainModel):
                visit(value.model_dump(mode="python"))
            elif isinstance(value, dict):
                for key, nested in value.items():
                    if str(key) == "metadata":
                        _validate_experiment_metadata(nested)
                    visit(nested)
            elif isinstance(value, list):
                for nested in value:
                    visit(nested)

        visit(self.benchmark_manifest)
        visit(self.input_set)
        visit(self.experiment_artifact)
        visit(self.reasoning_sessions)
        visit(self.case_run_records_by_condition)

    @classmethod
    def create(
        cls,
        *,
        manifest: BenchmarkManifest,
        input_set: RealExperimentInputSet,
        experiment_artifact: RealModelExperimentArtifact,
        reasoning_sessions: list[ExperimentCaseReasoningSession],
        case_run_records_by_condition: list[ExperimentConditionCaseRun],
        metadata: Metadata | None = None,
    ) -> "RealModelExecutionArchive":
        plan = experiment_artifact.experiment_plan
        values = {
            "contract": PHASE10D_EXECUTION_CONTRACT,
            "experiment_plan_id": plan.id,
            "benchmark_manifest_id": manifest.id,
            "input_set_id": input_set.id,
            "experiment_artifact_id": experiment_artifact.id,
            "reasoning_session_binding_ids": [
                item.id for item in reasoning_sessions
            ],
            "archived_case_run_binding_ids": [
                item.id for item in case_run_records_by_condition
            ],
        }
        return cls(
            id=real_model_execution_archive_id(**values),
            contract=PHASE10D_EXECUTION_CONTRACT,
            experiment_plan_id=plan.id,
            benchmark_manifest=manifest,
            input_set=input_set,
            experiment_artifact=experiment_artifact,
            reasoning_sessions=reasoning_sessions,
            case_run_records_by_condition=case_run_records_by_condition,
            metadata=metadata or {},
        )
