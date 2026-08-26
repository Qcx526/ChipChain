"""Phase 10D Step 1 condition accounting and canonical artifact envelope."""

from __future__ import annotations

from pydantic import Field, field_validator, model_validator

from chipchain.evaluation.ablation_models import (
    AblationComparisonReport,
    AblationConditionExecutionFailure,
    AblationConditionResult,
    ContextObjectiveUpperBoundResult,
    PromptVisibilityAudit,
)
from chipchain.evaluation.benchmark_models import BenchmarkEvaluationReport
from chipchain.evaluation.enums import (
    AblationConditionKind,
    ExperimentExecutionMode,
    ModelInvocationDisposition,
    PromptVisibilityAuditStatus,
)
from chipchain.evaluation.experiment_models import (
    PHASE10D_EXPERIMENT_CONTRACT,
    PHASE10D_PROVIDER_ROLE_ORDER,
    ModelInvocationRecord,
    RealModelExperimentPlan,
    _MODEL_CONDITIONS,
    _validate_experiment_metadata,
    expected_experiment_invocation_keys,
)
from chipchain.evaluation.models import _canonical_hash
from chipchain.models.common import DomainModel, Identifier, Metadata


PHASE10D_ARTIFACT_CONTRACT = "phase10d_real_model_experiment_artifact_v1"


def _validate_comparison_provenance_binding(
    condition_records: list["RealExperimentConditionRecord"],
    comparison: AblationComparisonReport,
) -> None:
    """Require Phase 10C comparison children from this exact execution."""

    execution_by_kind = {
        item.condition_kind: item for item in condition_records
    }
    comparison_by_kind: dict[AblationConditionKind, AblationConditionResult] = {
        item.condition_kind: item for item in comparison.condition_results
    }
    if set(execution_by_kind) != set(AblationConditionKind) or set(
        comparison_by_kind
    ) != set(AblationConditionKind):
        raise ValueError("comparison provenance requires all four conditions")

    for condition_kind in AblationConditionKind:
        execution = execution_by_kind[condition_kind]
        result = comparison_by_kind[condition_kind]
        execution_failure = execution.condition_failure
        comparison_failure = result.execution_failure
        if (execution_failure is None) is not (comparison_failure is None):
            raise ValueError(
                "comparison condition success/failure provenance mismatch"
            )
        if execution_failure is not None:
            if (
                comparison_failure is None
                or execution_failure.id != comparison_failure.id
            ):
                raise ValueError("comparison condition failure ID mismatch")
        else:
            execution_output = (
                execution.benchmark_evaluation_report
                or execution.context_objective_upper_bound_result
            )
            comparison_output = (
                result.benchmark_evaluation_report
                or result.context_objective_upper_bound_result
            )
            if execution_output is None:
                raise ValueError(
                    "comparison requires explicit failure for incomplete condition"
                )
            if (
                comparison_output is None
                or execution_output.id != comparison_output.id
            ):
                raise ValueError("comparison condition output ID mismatch")

        execution_audit_ids = sorted(
            audit.id for audit in execution.prompt_visibility_audits
        )
        if sorted(result.prompt_visibility_audit_ids) != execution_audit_ids:
            raise ValueError("comparison prompt-audit provenance mismatch")


def real_experiment_condition_record_id(
    *,
    experiment_plan_id: str,
    condition_kind: AblationConditionKind,
    benchmark_manifest_id: str,
    invocation_record_ids: list[str],
    benchmark_evaluation_report_id: str | None,
    context_objective_upper_bound_result_id: str | None,
    prompt_visibility_audit_ids: list[str],
    condition_failure_id: str | None,
) -> str:
    """Bind exact per-condition execution and output accounting."""

    return _canonical_hash(
        "real-experiment-condition-record",
        {
            "benchmark_evaluation_report_id": benchmark_evaluation_report_id,
            "benchmark_manifest_id": benchmark_manifest_id,
            "condition_failure_id": condition_failure_id,
            "condition_kind": AblationConditionKind(condition_kind).value,
            "context_objective_upper_bound_result_id": (
                context_objective_upper_bound_result_id
            ),
            "experiment_plan_id": experiment_plan_id,
            "invocation_record_ids": sorted(invocation_record_ids),
            "prompt_visibility_audit_ids": sorted(
                prompt_visibility_audit_ids
            ),
        },
    )


class RealExperimentConditionRecord(DomainModel):
    """One explicit record for every condition in the frozen matrix."""

    id: Identifier
    experiment_plan_id: Identifier
    condition_kind: AblationConditionKind
    benchmark_manifest_id: Identifier
    invocation_records: list[ModelInvocationRecord] = Field(default_factory=list)
    benchmark_evaluation_report: BenchmarkEvaluationReport | None = None
    context_objective_upper_bound_result: (
        ContextObjectiveUpperBoundResult | None
    ) = None
    prompt_visibility_audits: list[PromptVisibilityAudit] = Field(
        default_factory=list
    )
    condition_failure: AblationConditionExecutionFailure | None = None
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("invocation_records")
    @classmethod
    def normalize_invocations(
        cls, values: list[ModelInvocationRecord]
    ) -> list[ModelInvocationRecord]:
        if len(values) != len({item.id for item in values}):
            raise ValueError("condition invocation record IDs must be unique")
        if len(values) != len({item.invocation_key.id for item in values}):
            raise ValueError("condition invocation keys must be unique")
        return sorted(
            values,
            key=lambda item: (
                item.invocation_key.benchmark_case_id,
                PHASE10D_PROVIDER_ROLE_ORDER.index(item.invocation_key.role),
            ),
        )

    @field_validator("prompt_visibility_audits")
    @classmethod
    def normalize_audits(
        cls, values: list[PromptVisibilityAudit]
    ) -> list[PromptVisibilityAudit]:
        if len(values) != len({item.id for item in values}):
            raise ValueError("condition prompt audit IDs must be unique")
        if len(values) != len({item.prompt_sha256 for item in values}):
            raise ValueError("condition prompt audit hashes must be unique")
        return sorted(values, key=lambda item: item.prompt_sha256)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_experiment_metadata(value)

    @model_validator(mode="after")
    def validate_shape_and_identity(self) -> "RealExperimentConditionRecord":
        is_model = self.condition_kind in _MODEL_CONDITIONS
        if is_model:
            if not self.invocation_records:
                raise ValueError("model condition requires invocation accounting")
            if any(
                item.invocation_key.experiment_plan_id
                != self.experiment_plan_id
                for item in self.invocation_records
            ):
                raise ValueError("condition invocation experiment plan mismatch")
            if any(
                item.invocation_key.condition_kind is not self.condition_kind
                for item in self.invocation_records
            ):
                raise ValueError("condition contains invocation from another condition")
            self._validate_role_accounting_and_fail_stop()
            all_completed = all(
                item.disposition is ModelInvocationDisposition.COMPLETED
                for item in self.invocation_records
            )
            if all_completed:
                if (self.benchmark_evaluation_report is None) is (
                    self.condition_failure is None
                ):
                    raise ValueError(
                        "completed invocations require report xor downstream failure"
                    )
            elif self.benchmark_evaluation_report is not None:
                raise ValueError("incomplete model condition cannot contain report")
            if self.context_objective_upper_bound_result is not None:
                raise ValueError("model condition cannot contain upper-bound result")
        elif self.invocation_records:
            raise ValueError("non-provider condition cannot contain model invocation")

        if self.condition_kind is AblationConditionKind.NO_MODEL_BASELINE:
            if self.prompt_visibility_audits:
                raise ValueError("no-model condition cannot contain prompt audits")
            if self.context_objective_upper_bound_result is not None:
                raise ValueError("no-model condition cannot contain upper-bound result")
            if (self.benchmark_evaluation_report is None) is (
                self.condition_failure is None
            ):
                raise ValueError("no-model condition requires report xor failure")
        elif (
            self.condition_kind
            is AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND
        ):
            if self.prompt_visibility_audits:
                raise ValueError("upper-bound condition cannot contain prompt audits")
            if self.benchmark_evaluation_report is not None:
                raise ValueError("upper-bound condition cannot contain Phase 10B report")
            if (self.context_objective_upper_bound_result is None) is (
                self.condition_failure is None
            ):
                raise ValueError("upper-bound condition requires result xor failure")
        elif self.condition_kind is AblationConditionKind.FULL_CONTEXT_MODEL:
            if self.prompt_visibility_audits:
                raise ValueError("FULL condition does not bind masked prompt audits")
        else:
            self._validate_masked_audit_bindings()

        output = (
            self.benchmark_evaluation_report
            or self.context_objective_upper_bound_result
        )
        if output is not None and (
            output.benchmark_manifest_id != self.benchmark_manifest_id
        ):
            raise ValueError("condition output benchmark manifest mismatch")
        if self.condition_failure is not None and (
            self.condition_failure.condition_kind is not self.condition_kind
        ):
            raise ValueError("condition failure kind mismatch")
        expected = real_experiment_condition_record_id(
            experiment_plan_id=self.experiment_plan_id,
            condition_kind=self.condition_kind,
            benchmark_manifest_id=self.benchmark_manifest_id,
            invocation_record_ids=[item.id for item in self.invocation_records],
            benchmark_evaluation_report_id=(
                self.benchmark_evaluation_report.id
                if self.benchmark_evaluation_report is not None
                else None
            ),
            context_objective_upper_bound_result_id=(
                self.context_objective_upper_bound_result.id
                if self.context_objective_upper_bound_result is not None
                else None
            ),
            prompt_visibility_audit_ids=[
                item.id for item in self.prompt_visibility_audits
            ],
            condition_failure_id=(
                self.condition_failure.id
                if self.condition_failure is not None
                else None
            ),
        )
        if self.id != expected:
            raise ValueError("RealExperimentConditionRecord ID is not deterministic")
        return self

    def _validate_masked_audit_bindings(self) -> None:
        invocation_prompt_hashes = sorted(
            item.prompt_sha256
            for item in self.invocation_records
            if item.prompt_sha256 is not None
        )
        audit_prompt_hashes = sorted(
            item.prompt_sha256 for item in self.prompt_visibility_audits
        )
        if audit_prompt_hashes != invocation_prompt_hashes:
            raise ValueError(
                "MASKED condition requires one audit per attempted prompt hash"
            )

    def _validate_role_accounting_and_fail_stop(self) -> None:
        by_case: dict[str, dict[object, ModelInvocationRecord]] = {}
        for record in self.invocation_records:
            case_records = by_case.setdefault(
                record.invocation_key.benchmark_case_id, {}
            )
            role = record.invocation_key.role
            if role in case_records:
                raise ValueError("condition contains duplicate case role")
            if record.invocation_key.repetition_index != 0:
                raise ValueError("Phase 10D v1 requires repetition zero")
            case_records[role] = record

        expected_roles = set(PHASE10D_PROVIDER_ROLE_ORDER)
        for case_records in by_case.values():
            if set(case_records) != expected_roles:
                raise ValueError("model condition requires every provider role")
            ordered = [case_records[role] for role in PHASE10D_PROVIDER_ROLE_ORDER]
            failed_indexes = [
                index
                for index, record in enumerate(ordered)
                if record.disposition is ModelInvocationDisposition.FAILED
            ]
            if not failed_indexes:
                if any(
                    record.disposition
                    is not ModelInvocationDisposition.COMPLETED
                    for record in ordered
                ):
                    raise ValueError("invalid sequential fail-stop disposition shape")
                continue
            if len(failed_indexes) != 1:
                raise ValueError("one case may contain at most one failed role")
            failed_index = failed_indexes[0]
            failed_role = PHASE10D_PROVIDER_ROLE_ORDER[failed_index]
            if any(
                record.disposition is not ModelInvocationDisposition.COMPLETED
                for record in ordered[:failed_index]
            ) or any(
                record.disposition is not ModelInvocationDisposition.NOT_ATTEMPTED
                or record.blocked_by_role is not failed_role
                for record in ordered[failed_index + 1 :]
            ):
                raise ValueError("invalid sequential fail-stop disposition shape")

    @classmethod
    def create(
        cls,
        plan: RealModelExperimentPlan,
        *,
        condition_kind: AblationConditionKind | str,
        invocation_records: list[ModelInvocationRecord] | None = None,
        benchmark_evaluation_report: BenchmarkEvaluationReport | None = None,
        context_objective_upper_bound_result: (
            ContextObjectiveUpperBoundResult | None
        ) = None,
        prompt_visibility_audits: list[PromptVisibilityAudit] | None = None,
        condition_failure: AblationConditionExecutionFailure | None = None,
        metadata: Metadata | None = None,
    ) -> "RealExperimentConditionRecord":
        """Create one record after exact plan/case/provider accounting."""

        if not isinstance(plan, RealModelExperimentPlan):
            raise TypeError("condition record requires RealModelExperimentPlan")
        condition = AblationConditionKind(condition_kind)
        records = [
            ModelInvocationRecord.model_validate(item.model_dump(mode="json"))
            for item in (invocation_records or [])
        ]
        audits = [
            PromptVisibilityAudit.model_validate(item.model_dump(mode="json"))
            for item in (prompt_visibility_audits or [])
        ]
        report = (
            BenchmarkEvaluationReport.model_validate(
                benchmark_evaluation_report.model_dump(mode="json")
            )
            if benchmark_evaluation_report is not None
            else None
        )
        upper_result = (
            ContextObjectiveUpperBoundResult.model_validate(
                context_objective_upper_bound_result.model_dump(mode="json")
            )
            if context_objective_upper_bound_result is not None
            else None
        )
        failure = (
            AblationConditionExecutionFailure.model_validate(
                condition_failure.model_dump(mode="json")
            )
            if condition_failure is not None
            else None
        )
        if condition in _MODEL_CONDITIONS:
            expected_keys = expected_experiment_invocation_keys(
                plan, condition_kind=condition
            )
            if len(records) != len(expected_keys) or {
                item.invocation_key.id for item in records
            } != {item.id for item in expected_keys}:
                raise ValueError(
                    "model condition must account for every planned case role"
                )
            for record in records:
                if (
                    record.invocation_key.experiment_plan_id != plan.id
                    or record.invocation_key.condition_kind is not condition
                    or record.invocation_key.repetition_index != 0
                    or record.provider_descriptor_id
                    != plan.provider_descriptor.id
                    or record.execution_mode is not plan.execution_mode
                    or record.structured_output_schema_name
                    != plan.provider_descriptor.schema_name
                ):
                    raise ValueError("condition invocation plan binding mismatch")
        elif records:
            raise ValueError("non-provider condition cannot contain model invocation")
        if failure is not None and (
            failure.ablation_plan_id != plan.ablation_plan_id
        ):
            raise ValueError("condition failure ablation plan mismatch")
        output = report or upper_result
        if output is not None and (
            output.benchmark_manifest_id,
            output.benchmark_version,
        ) != (plan.benchmark_manifest_id, plan.benchmark_version):
            raise ValueError("condition output frozen benchmark mismatch")
        values = {
            "experiment_plan_id": plan.id,
            "condition_kind": condition,
            "benchmark_manifest_id": plan.benchmark_manifest_id,
            "invocation_record_ids": [item.id for item in records],
            "benchmark_evaluation_report_id": (
                report.id if report is not None else None
            ),
            "context_objective_upper_bound_result_id": (
                upper_result.id if upper_result is not None else None
            ),
            "prompt_visibility_audit_ids": [item.id for item in audits],
            "condition_failure_id": (
                failure.id if failure is not None else None
            ),
        }
        return cls(
            id=real_experiment_condition_record_id(**values),
            experiment_plan_id=plan.id,
            condition_kind=condition,
            benchmark_manifest_id=plan.benchmark_manifest_id,
            invocation_records=records,
            benchmark_evaluation_report=report,
            context_objective_upper_bound_result=upper_result,
            prompt_visibility_audits=audits,
            condition_failure=failure,
            metadata=metadata or {},
        )


def real_model_experiment_artifact_id(
    *,
    contract: str,
    experiment_plan_id: str,
    condition_record_ids: list[str],
    ablation_comparison_report_id: str | None,
    provider_configuration_comparable: bool,
    benchmark_comparable: bool,
    prompt_visibility_valid: bool,
    execution_complete: bool,
) -> str:
    """Bind exact records and derived experiment-quality state."""

    return _canonical_hash(
        "real-model-experiment-artifact",
        {
            "ablation_comparison_report_id": ablation_comparison_report_id,
            "benchmark_comparable": benchmark_comparable,
            "condition_record_ids": sorted(condition_record_ids),
            "contract": contract,
            "execution_complete": execution_complete,
            "experiment_plan_id": experiment_plan_id,
            "prompt_visibility_valid": prompt_visibility_valid,
            "provider_configuration_comparable": (
                provider_configuration_comparable
            ),
        },
    )


class RealModelExperimentArtifact(DomainModel):
    """Canonical hash-only provenance envelope, not a performance conclusion."""

    id: Identifier
    contract: Identifier
    experiment_plan: RealModelExperimentPlan
    condition_records: list[RealExperimentConditionRecord]
    ablation_comparison_report: AblationComparisonReport | None = None
    provider_configuration_comparable: bool
    benchmark_comparable: bool
    prompt_visibility_valid: bool
    execution_complete: bool
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("condition_records")
    @classmethod
    def normalize_condition_records(
        cls, values: list[RealExperimentConditionRecord]
    ) -> list[RealExperimentConditionRecord]:
        if len(values) != len(AblationConditionKind) or {
            item.condition_kind for item in values
        } != set(AblationConditionKind):
            raise ValueError("experiment artifact requires all four conditions")
        return sorted(values, key=lambda item: item.condition_kind.value)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_experiment_metadata(value)

    @model_validator(mode="after")
    def validate_bindings_quality_and_identity(self) -> "RealModelExperimentArtifact":
        if self.contract != PHASE10D_ARTIFACT_CONTRACT:
            raise ValueError("unsupported real-model experiment artifact contract")
        if self.experiment_plan.contract != PHASE10D_EXPERIMENT_CONTRACT:
            raise ValueError("artifact contains unsupported experiment plan")
        self._validate_nested_metadata()
        if any(
            item.experiment_plan_id != self.experiment_plan.id
            or item.benchmark_manifest_id
            != self.experiment_plan.benchmark_manifest_id
            for item in self.condition_records
        ):
            raise ValueError("condition record experiment binding mismatch")
        if any(
            item.condition_failure is not None
            and item.condition_failure.ablation_plan_id
            != self.experiment_plan.ablation_plan_id
            for item in self.condition_records
        ):
            raise ValueError("artifact condition failure ablation binding mismatch")
        for condition in self.condition_records:
            output = (
                condition.benchmark_evaluation_report
                or condition.context_objective_upper_bound_result
            )
            if output is not None and (
                output.benchmark_manifest_id,
                output.benchmark_version,
            ) != (
                self.experiment_plan.benchmark_manifest_id,
                self.experiment_plan.benchmark_version,
            ):
                raise ValueError("artifact condition output benchmark mismatch")
        by_kind = {item.condition_kind: item for item in self.condition_records}
        for condition in _MODEL_CONDITIONS:
            records = by_kind[condition].invocation_records
            expected_keys = expected_experiment_invocation_keys(
                self.experiment_plan, condition_kind=condition
            )
            if len(records) != len(expected_keys) or {
                item.invocation_key.id for item in records
            } != {item.id for item in expected_keys}:
                raise ValueError(
                    "artifact model condition case-role accounting mismatch"
                )
            if any(
                item.invocation_key.experiment_plan_id != self.experiment_plan.id
                or item.invocation_key.condition_kind is not condition
                or item.provider_descriptor_id
                != self.experiment_plan.provider_descriptor.id
                or item.execution_mode is not self.experiment_plan.execution_mode
                or item.structured_output_schema_name
                != self.experiment_plan.provider_descriptor.schema_name
                for item in records
            ):
                raise ValueError("artifact invocation provenance mismatch")
        comparison = self.ablation_comparison_report
        if comparison is not None:
            if (
                comparison.ablation_plan_id
                != self.experiment_plan.ablation_plan_id
                or comparison.benchmark_manifest_id
                != self.experiment_plan.benchmark_manifest_id
            ):
                raise ValueError("artifact ablation comparison binding mismatch")
            _validate_comparison_provenance_binding(
                self.condition_records, comparison
            )
        expected_flags = self._derive_quality_flags()
        actual_flags = (
            self.provider_configuration_comparable,
            self.benchmark_comparable,
            self.prompt_visibility_valid,
            self.execution_complete,
        )
        if actual_flags != expected_flags:
            raise ValueError("experiment quality flags are not derived")
        expected = real_model_experiment_artifact_id(
            contract=self.contract,
            experiment_plan_id=self.experiment_plan.id,
            condition_record_ids=[item.id for item in self.condition_records],
            ablation_comparison_report_id=(
                comparison.id if comparison is not None else None
            ),
            provider_configuration_comparable=self.provider_configuration_comparable,
            benchmark_comparable=self.benchmark_comparable,
            prompt_visibility_valid=self.prompt_visibility_valid,
            execution_complete=self.execution_complete,
        )
        if self.id != expected:
            raise ValueError("RealModelExperimentArtifact ID is not deterministic")
        return self

    def _validate_nested_metadata(self) -> None:
        """Prevent nested typed outputs from reintroducing forbidden content."""

        def visit(value: object) -> None:
            if isinstance(value, DomainModel):
                visit(value.model_dump(mode="python"))
            elif isinstance(value, dict):
                for key, nested in value.items():
                    normalized = "".join(
                        character
                        for character in str(key).lower()
                        if character.isalnum()
                    )
                    if normalized == "metadata":
                        _validate_experiment_metadata(nested)
                    visit(nested)
            elif isinstance(value, list):
                for nested in value:
                    visit(nested)

        visit(self.experiment_plan)
        visit(self.condition_records)
        if self.ablation_comparison_report is not None:
            visit(self.ablation_comparison_report)

    def _derive_quality_flags(self) -> tuple[bool, bool, bool, bool]:
        records = [
            invocation
            for condition in self.condition_records
            for invocation in condition.invocation_records
        ]
        provider_comparable = bool(records) and all(
            item.provider_descriptor_id
            == self.experiment_plan.provider_descriptor.id
            for item in records
        )
        benchmark_comparable = all(
            item.benchmark_manifest_id
            == self.experiment_plan.benchmark_manifest_id
            for item in self.condition_records
        )
        masked = next(
            item
            for item in self.condition_records
            if item.condition_kind
            is AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
        )
        masked_hashes = sorted(
            item.prompt_sha256
            for item in masked.invocation_records
            if item.prompt_sha256 is not None
        )
        passed_audit_hashes = sorted(
            item.prompt_sha256
            for item in masked.prompt_visibility_audits
            if item.status is PromptVisibilityAuditStatus.PASS
        )
        prompt_visibility_valid = bool(masked_hashes) and (
            passed_audit_hashes == masked_hashes
            and len(masked.prompt_visibility_audits) == len(masked_hashes)
        )
        execution_complete = all(
            condition.condition_failure is None
            and (
                all(
                    item.disposition is ModelInvocationDisposition.COMPLETED
                    for item in condition.invocation_records
                )
                if condition.condition_kind in _MODEL_CONDITIONS
                else True
            )
            and (
                condition.context_objective_upper_bound_result is not None
                if condition.condition_kind
                is AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND
                else condition.benchmark_evaluation_report is not None
            )
            for condition in self.condition_records
        )
        return (
            provider_comparable,
            benchmark_comparable,
            prompt_visibility_valid,
            execution_complete,
        )

    @property
    def is_real_provider_result(self) -> bool:
        """Prevent offline contract fixtures from being called real experiments."""

        return bool(
            self.experiment_plan.execution_mode
            is ExperimentExecutionMode.REAL_PROVIDER
            and self.provider_configuration_comparable
            and self.benchmark_comparable
            and self.prompt_visibility_valid
            and self.execution_complete
        )

    @classmethod
    def create(
        cls,
        *,
        experiment_plan: RealModelExperimentPlan,
        condition_records: list[RealExperimentConditionRecord],
        ablation_comparison_report: AblationComparisonReport | None = None,
        metadata: Metadata | None = None,
    ) -> "RealModelExperimentArtifact":
        """Assemble one immutable envelope without executing any provider."""

        if not isinstance(experiment_plan, RealModelExperimentPlan):
            raise TypeError("artifact requires RealModelExperimentPlan")
        plan = RealModelExperimentPlan.model_validate(
            experiment_plan.model_dump(mode="json")
        )
        records = [
            RealExperimentConditionRecord.model_validate(item.model_dump(mode="json"))
            for item in condition_records
        ]
        probe = cls.model_construct(
            condition_records=records,
            experiment_plan=plan,
        )
        flags = probe._derive_quality_flags()
        comparison = (
            AblationComparisonReport.model_validate(
                ablation_comparison_report.model_dump(mode="json")
            )
            if ablation_comparison_report is not None
            else None
        )
        comparison_id = comparison.id if comparison is not None else None
        identity = real_model_experiment_artifact_id(
            contract=PHASE10D_ARTIFACT_CONTRACT,
            experiment_plan_id=plan.id,
            condition_record_ids=[item.id for item in records],
            ablation_comparison_report_id=comparison_id,
            provider_configuration_comparable=flags[0],
            benchmark_comparable=flags[1],
            prompt_visibility_valid=flags[2],
            execution_complete=flags[3],
        )
        return cls(
            id=identity,
            contract=PHASE10D_ARTIFACT_CONTRACT,
            experiment_plan=plan,
            condition_records=records,
            ablation_comparison_report=comparison,
            provider_configuration_comparable=flags[0],
            benchmark_comparable=flags[1],
            prompt_visibility_valid=flags[2],
            execution_complete=flags[3],
            metadata=metadata or {},
        )
