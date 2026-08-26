"""Deterministic Phase 10C ablation protocol and comparison contracts."""

from __future__ import annotations

import hashlib
import json
import re

from pydantic import Field, field_validator, model_validator

from chipchain.evaluation.benchmark_models import (
    BenchmarkEvaluationReport,
    EvaluationMetricResult,
    _validate_metadata,
)
from chipchain.evaluation.enums import (
    AblationConditionFailureCode,
    AblationConditionFailureStage,
    AblationConditionKind,
    EvaluationMetricName,
    PromptVisibilityAuditStatus,
)
from chipchain.evaluation.models import _canonical_hash
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.reasoning.enums import ReasoningPromptVisibility


PHASE10C_ABLATION_CONTRACT = "phase10c_ablation_protocol_v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _unique_sorted(values: list[str], label: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
    return sorted(values)


def ablation_condition_spec_id(
    *,
    condition_kind: AblationConditionKind,
    prompt_visibility: ReasoningPromptVisibility,
    requires_model_provider: bool,
    uses_model_claim_gate: bool,
    uses_context_objective_upper_bound: bool,
    repetitions: int,
) -> str:
    return _canonical_hash(
        "ablation-condition-spec",
        {
            "condition_kind": condition_kind.value,
            "prompt_visibility": prompt_visibility.value,
            "repetitions": repetitions,
            "requires_model_provider": requires_model_provider,
            "uses_context_objective_upper_bound": (
                uses_context_objective_upper_bound
            ),
            "uses_model_claim_gate": uses_model_claim_gate,
        },
    )


class AblationConditionSpec(DomainModel):
    """One predeclared condition with no user-selectable semantic switches."""

    id: Identifier
    condition_kind: AblationConditionKind
    prompt_visibility: ReasoningPromptVisibility
    requires_model_provider: bool
    uses_model_claim_gate: bool
    uses_context_objective_upper_bound: bool
    repetitions: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_contract(self) -> "AblationConditionSpec":
        expected = _condition_semantics(self.condition_kind)
        actual = (
            self.prompt_visibility,
            self.requires_model_provider,
            self.uses_model_claim_gate,
            self.uses_context_objective_upper_bound,
            self.repetitions,
        )
        if actual != expected:
            raise ValueError("ablation condition semantics are contradictory")
        expected_id = ablation_condition_spec_id(
            condition_kind=self.condition_kind,
            prompt_visibility=self.prompt_visibility,
            requires_model_provider=self.requires_model_provider,
            uses_model_claim_gate=self.uses_model_claim_gate,
            uses_context_objective_upper_bound=(
                self.uses_context_objective_upper_bound
            ),
            repetitions=self.repetitions,
        )
        if self.id != expected_id:
            raise ValueError("AblationConditionSpec ID is not deterministic")
        return self

    @classmethod
    def create(cls, kind: AblationConditionKind | str) -> "AblationConditionSpec":
        condition = AblationConditionKind(kind)
        visibility, provider, claim_gate, upper, repetitions = (
            _condition_semantics(condition)
        )
        identity = ablation_condition_spec_id(
            condition_kind=condition,
            prompt_visibility=visibility,
            requires_model_provider=provider,
            uses_model_claim_gate=claim_gate,
            uses_context_objective_upper_bound=upper,
            repetitions=repetitions,
        )
        return cls(
            id=identity,
            condition_kind=condition,
            prompt_visibility=visibility,
            requires_model_provider=provider,
            uses_model_claim_gate=claim_gate,
            uses_context_objective_upper_bound=upper,
            repetitions=repetitions,
        )


def _condition_semantics(
    kind: AblationConditionKind,
) -> tuple[ReasoningPromptVisibility, bool, bool, bool, int]:
    if kind is AblationConditionKind.FULL_CONTEXT_MODEL:
        return ReasoningPromptVisibility.FULL_CONTEXT, True, True, False, 1
    if kind is AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL:
        return ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT, True, True, False, 1
    if kind is AblationConditionKind.NO_MODEL_BASELINE:
        return ReasoningPromptVisibility.FULL_CONTEXT, False, True, False, 1
    return ReasoningPromptVisibility.FULL_CONTEXT, False, False, True, 1


def ablation_experiment_plan_id(
    *,
    contract: str,
    benchmark_manifest_id: str,
    benchmark_version: str,
    condition_spec_ids: list[str],
    primary_model_condition: AblationConditionKind,
) -> str:
    return _canonical_hash(
        "ablation-experiment-plan",
        {
            "benchmark_manifest_id": benchmark_manifest_id,
            "benchmark_version": benchmark_version,
            "condition_spec_ids": sorted(condition_spec_ids),
            "contract": contract,
            "primary_model_condition": primary_model_condition.value,
        },
    )


class AblationExperimentPlan(DomainModel):
    """Frozen four-condition Phase 10C protocol declared before outputs."""

    id: Identifier
    contract: Identifier
    benchmark_manifest_id: Identifier
    benchmark_version: Identifier
    condition_specs: list[AblationConditionSpec]
    primary_model_condition: AblationConditionKind
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("condition_specs")
    @classmethod
    def normalize_specs(
        cls, values: list[AblationConditionSpec]
    ) -> list[AblationConditionSpec]:
        if len(values) != len(AblationConditionKind) or {
            item.condition_kind for item in values
        } != set(AblationConditionKind):
            raise ValueError("ablation plan requires exactly all four conditions")
        return sorted(values, key=lambda item: item.condition_kind.value)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "AblationExperimentPlan":
        if self.contract != PHASE10C_ABLATION_CONTRACT:
            raise ValueError("unsupported ablation protocol contract")
        if self.primary_model_condition not in {
            AblationConditionKind.FULL_CONTEXT_MODEL,
            AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        }:
            raise ValueError("primary model condition must use a model provider")
        expected = ablation_experiment_plan_id(
            contract=self.contract,
            benchmark_manifest_id=self.benchmark_manifest_id,
            benchmark_version=self.benchmark_version,
            condition_spec_ids=[item.id for item in self.condition_specs],
            primary_model_condition=self.primary_model_condition,
        )
        if self.id != expected:
            raise ValueError("AblationExperimentPlan ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        benchmark_manifest_id: str,
        benchmark_version: str,
        primary_model_condition: AblationConditionKind | str = (
            AblationConditionKind.FULL_CONTEXT_MODEL
        ),
        metadata: Metadata | None = None,
    ) -> "AblationExperimentPlan":
        specs = [AblationConditionSpec.create(item) for item in AblationConditionKind]
        primary = AblationConditionKind(primary_model_condition)
        identity = ablation_experiment_plan_id(
            contract=PHASE10C_ABLATION_CONTRACT,
            benchmark_manifest_id=benchmark_manifest_id,
            benchmark_version=benchmark_version,
            condition_spec_ids=[item.id for item in specs],
            primary_model_condition=primary,
        )
        return cls(
            id=identity,
            contract=PHASE10C_ABLATION_CONTRACT,
            benchmark_manifest_id=benchmark_manifest_id,
            benchmark_version=benchmark_version,
            condition_specs=specs,
            primary_model_condition=primary,
            metadata=metadata or {},
        )


def prompt_visibility_audit_id(
    *,
    prompt_sha256: str,
    hidden_reference_ids: list[str],
    leaked_reference_ids: list[str],
    status: PromptVisibilityAuditStatus,
) -> str:
    return _canonical_hash(
        "prompt-visibility-audit",
        {
            "hidden_reference_ids": sorted(hidden_reference_ids),
            "leaked_reference_ids": sorted(leaked_reference_ids),
            "prompt_sha256": prompt_sha256,
            "status": status.value,
        },
    )


class PromptVisibilityAudit(DomainModel):
    """Exact-reference experiment audit; never Evidence or verification."""

    id: Identifier
    prompt_sha256: Identifier
    hidden_reference_ids: list[Identifier]
    leaked_reference_ids: list[Identifier]
    status: PromptVisibilityAuditStatus
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("prompt_sha256")
    @classmethod
    def validate_prompt_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("prompt SHA-256 must be lowercase hexadecimal")
        return value

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_metadata(value)

    @field_validator("hidden_reference_ids", "leaked_reference_ids")
    @classmethod
    def normalize_ids(cls, values: list[str]) -> list[str]:
        return _unique_sorted(values, "prompt audit references")

    @model_validator(mode="after")
    def validate_audit(self) -> "PromptVisibilityAudit":
        if not set(self.leaked_reference_ids).issubset(self.hidden_reference_ids):
            raise ValueError("leaked references must be hidden-reference subset")
        expected_status = (
            PromptVisibilityAuditStatus.LEAK_DETECTED
            if self.leaked_reference_ids
            else PromptVisibilityAuditStatus.PASS
        )
        if self.status is not expected_status:
            raise ValueError("prompt visibility audit status is not derived")
        expected = prompt_visibility_audit_id(
            prompt_sha256=self.prompt_sha256,
            hidden_reference_ids=self.hidden_reference_ids,
            leaked_reference_ids=self.leaked_reference_ids,
            status=self.status,
        )
        if self.id != expected:
            raise ValueError("PromptVisibilityAudit ID is not deterministic")
        return self


def context_objective_upper_bound_rate_id(
    *, numerator_ids: list[str], denominator_ids: list[str]
) -> str:
    return _canonical_hash(
        "context-objective-upper-bound-rate",
        {
            "denominator_ids": sorted(denominator_ids),
            "numerator_ids": sorted(numerator_ids),
        },
    )


class ContextObjectiveUpperBoundRate(DomainModel):
    """Exact context/verifier diagnostic, explicitly not VerificationHitRate."""

    id: Identifier
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    numerator_ids: list[Identifier]
    denominator_ids: list[Identifier]
    defined: bool

    @field_validator("numerator_ids")
    @classmethod
    def normalize_numerator_ids(cls, values: list[str]) -> list[str]:
        return _unique_sorted(values, "upper-bound numerator IDs")

    @field_validator("denominator_ids")
    @classmethod
    def normalize_denominator_ids(cls, values: list[str]) -> list[str]:
        return _unique_sorted(values, "upper-bound denominator IDs")

    @model_validator(mode="after")
    def validate_metric(self) -> "ContextObjectiveUpperBoundRate":
        if self.numerator != len(self.numerator_ids) or self.denominator != len(
            self.denominator_ids
        ):
            raise ValueError("upper-bound counts do not match exact cohorts")
        if not set(self.numerator_ids).issubset(self.denominator_ids):
            raise ValueError("upper-bound numerator must be denominator subset")
        if self.numerator > self.denominator:
            raise ValueError("upper-bound numerator cannot exceed denominator")
        if self.defined is not (self.denominator > 0):
            raise ValueError("upper-bound defined state is not derived")
        expected = context_objective_upper_bound_rate_id(
            numerator_ids=self.numerator_ids,
            denominator_ids=self.denominator_ids,
        )
        if self.id != expected:
            raise ValueError("ContextObjectiveUpperBoundRate ID is not deterministic")
        return self

    @property
    def ratio(self) -> float | None:
        return self.numerator / self.denominator if self.defined else None

    @classmethod
    def create(
        cls, *, numerator_ids: list[str], denominator_ids: list[str]
    ) -> "ContextObjectiveUpperBoundRate":
        numerator = _unique_sorted(numerator_ids, "upper-bound numerator IDs")
        denominator = _unique_sorted(denominator_ids, "upper-bound denominator IDs")
        identity = context_objective_upper_bound_rate_id(
            numerator_ids=numerator,
            denominator_ids=denominator,
        )
        return cls(
            id=identity,
            numerator=len(numerator),
            denominator=len(denominator),
            numerator_ids=numerator,
            denominator_ids=denominator,
            defined=bool(denominator),
        )


class ContextObjectiveUpperBoundResult(DomainModel):
    """Post-hoc exact-GT diagnostic with only the model-claim gate removed."""

    id: Identifier
    benchmark_manifest_id: Identifier
    benchmark_version: Identifier
    rate: ContextObjectiveUpperBoundRate
    primary_case_coverage: EvaluationMetricResult
    matched_ground_truth_chain_ids: list[Identifier]
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("matched_ground_truth_chain_ids")
    @classmethod
    def normalize_matches(cls, values: list[str]) -> list[str]:
        return _unique_sorted(values, "upper-bound Ground Truth IDs")

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "ContextObjectiveUpperBoundResult":
        if (
            self.primary_case_coverage.metric_name
            is not EvaluationMetricName.PRIMARY_CASE_COVERAGE
        ):
            raise ValueError("upper-bound coverage requires primary coverage metric")
        expected = _canonical_hash(
            "context-objective-upper-bound-result",
            {
                "benchmark_manifest_id": self.benchmark_manifest_id,
                "benchmark_version": self.benchmark_version,
                "matched_ground_truth_chain_ids": sorted(
                    self.matched_ground_truth_chain_ids
                ),
                "primary_case_coverage_id": self.primary_case_coverage.id,
                "rate_id": self.rate.id,
            },
        )
        if self.id != expected:
            raise ValueError("ContextObjectiveUpperBoundResult ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        benchmark_manifest_id: str,
        benchmark_version: str,
        rate: ContextObjectiveUpperBoundRate,
        primary_case_coverage: EvaluationMetricResult,
        matched_ground_truth_chain_ids: list[str],
        metadata: Metadata | None = None,
    ) -> "ContextObjectiveUpperBoundResult":
        matches = sorted(matched_ground_truth_chain_ids)
        identity = _canonical_hash(
            "context-objective-upper-bound-result",
            {
                "benchmark_manifest_id": benchmark_manifest_id,
                "benchmark_version": benchmark_version,
                "matched_ground_truth_chain_ids": matches,
                "primary_case_coverage_id": primary_case_coverage.id,
                "rate_id": rate.id,
            },
        )
        return cls(
            id=identity,
            benchmark_manifest_id=benchmark_manifest_id,
            benchmark_version=benchmark_version,
            rate=rate,
            primary_case_coverage=primary_case_coverage,
            matched_ground_truth_chain_ids=matches,
            metadata=metadata or {},
        )


class AblationConditionExecutionFailure(DomainModel):
    """Bounded experiment-level failure, not a semantic model outcome."""

    id: Identifier
    ablation_plan_id: Identifier
    condition_kind: AblationConditionKind
    stage: AblationConditionFailureStage
    failure_code: AblationConditionFailureCode
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "AblationConditionExecutionFailure":
        expected = _canonical_hash(
            "ablation-condition-execution-failure",
            {
                "ablation_plan_id": self.ablation_plan_id,
                "condition_kind": self.condition_kind.value,
                "failure_code": self.failure_code.value,
                "stage": self.stage.value,
            },
        )
        if self.id != expected:
            raise ValueError("condition failure ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        ablation_plan_id: str,
        condition_kind: AblationConditionKind | str,
        stage: AblationConditionFailureStage | str,
        failure_code: AblationConditionFailureCode | str,
        metadata: Metadata | None = None,
    ) -> "AblationConditionExecutionFailure":
        condition = AblationConditionKind(condition_kind)
        normalized_stage = AblationConditionFailureStage(stage)
        code = AblationConditionFailureCode(failure_code)
        identity = _canonical_hash(
            "ablation-condition-execution-failure",
            {
                "ablation_plan_id": ablation_plan_id,
                "condition_kind": condition.value,
                "failure_code": code.value,
                "stage": normalized_stage.value,
            },
        )
        return cls(
            id=identity,
            ablation_plan_id=ablation_plan_id,
            condition_kind=condition,
            stage=normalized_stage,
            failure_code=code,
            metadata=metadata or {},
        )


class AblationConditionResult(DomainModel):
    """One explicit success or failure for every predeclared condition."""

    id: Identifier
    ablation_plan_id: Identifier
    condition_kind: AblationConditionKind
    benchmark_manifest_id: Identifier
    benchmark_evaluation_report: BenchmarkEvaluationReport | None = None
    context_objective_upper_bound_result: ContextObjectiveUpperBoundResult | None = None
    prompt_visibility_audit_ids: list[Identifier] = Field(default_factory=list)
    execution_failure: AblationConditionExecutionFailure | None = None
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("prompt_visibility_audit_ids")
    @classmethod
    def normalize_audits(cls, values: list[str]) -> list[str]:
        return _unique_sorted(values, "prompt visibility audit IDs")

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_metadata(value)

    @model_validator(mode="after")
    def validate_shape_and_identity(self) -> "AblationConditionResult":
        model_condition = self.condition_kind is not (
            AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND
        )
        if self.execution_failure is not None:
            if (
                self.execution_failure.ablation_plan_id != self.ablation_plan_id
                or self.execution_failure.condition_kind is not self.condition_kind
            ):
                raise ValueError("condition failure binding mismatch")
            if (
                self.benchmark_evaluation_report is not None
                or self.context_objective_upper_bound_result is not None
            ):
                raise ValueError("failed condition cannot contain successful output")
        elif model_condition:
            if self.benchmark_evaluation_report is None or (
                self.context_objective_upper_bound_result is not None
            ):
                raise ValueError("model condition requires one Phase 10B report")
            if (
                self.benchmark_evaluation_report.benchmark_manifest_id
                != self.benchmark_manifest_id
            ):
                raise ValueError("condition report manifest mismatch")
        elif self.context_objective_upper_bound_result is None or (
            self.benchmark_evaluation_report is not None
        ):
            raise ValueError("upper-bound condition requires its diagnostic result")
        elif (
            self.context_objective_upper_bound_result.benchmark_manifest_id
            != self.benchmark_manifest_id
        ):
            raise ValueError("upper-bound result manifest mismatch")
        if self.condition_kind is AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL and (
            self.execution_failure is None and not self.prompt_visibility_audit_ids
        ):
            raise ValueError("masked condition requires prompt visibility audits")
        child_id = (
            self.execution_failure.id
            if self.execution_failure is not None
            else self.benchmark_evaluation_report.id
            if self.benchmark_evaluation_report is not None
            else self.context_objective_upper_bound_result.id
        )
        expected = _canonical_hash(
            "ablation-condition-result",
            {
                "ablation_plan_id": self.ablation_plan_id,
                "benchmark_manifest_id": self.benchmark_manifest_id,
                "child_result_id": child_id,
                "condition_kind": self.condition_kind.value,
                "prompt_visibility_audit_ids": sorted(
                    self.prompt_visibility_audit_ids
                ),
            },
        )
        if self.id != expected:
            raise ValueError("AblationConditionResult ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        ablation_plan_id: str,
        condition_kind: AblationConditionKind | str,
        benchmark_manifest_id: str,
        benchmark_evaluation_report: BenchmarkEvaluationReport | None = None,
        context_objective_upper_bound_result: (
            ContextObjectiveUpperBoundResult | None
        ) = None,
        prompt_visibility_audit_ids: list[str] | None = None,
        execution_failure: AblationConditionExecutionFailure | None = None,
        metadata: Metadata | None = None,
    ) -> "AblationConditionResult":
        condition = AblationConditionKind(condition_kind)
        audits = sorted(prompt_visibility_audit_ids or [])
        child = (
            execution_failure
            or benchmark_evaluation_report
            or context_objective_upper_bound_result
        )
        if child is None:
            raise ValueError("condition result requires success or explicit failure")
        identity = _canonical_hash(
            "ablation-condition-result",
            {
                "ablation_plan_id": ablation_plan_id,
                "benchmark_manifest_id": benchmark_manifest_id,
                "child_result_id": child.id,
                "condition_kind": condition.value,
                "prompt_visibility_audit_ids": audits,
            },
        )
        return cls(
            id=identity,
            ablation_plan_id=ablation_plan_id,
            condition_kind=condition,
            benchmark_manifest_id=benchmark_manifest_id,
            benchmark_evaluation_report=benchmark_evaluation_report,
            context_objective_upper_bound_result=(
                context_objective_upper_bound_result
            ),
            prompt_visibility_audit_ids=audits,
            execution_failure=execution_failure,
            metadata=metadata or {},
        )


class AblationMetricDelta(DomainModel):
    """Exact rational comparison without rounded identity values."""

    id: Identifier
    left_metric_id: Identifier | None = None
    right_metric_id: Identifier | None = None
    left_numerator: int | None = None
    left_denominator: int | None = None
    right_numerator: int | None = None
    right_denominator: int | None = None
    defined: bool

    @property
    def delta(self) -> float | None:
        if not self.defined:
            return None
        return (self.left_numerator / self.left_denominator) - (
            self.right_numerator / self.right_denominator
        )

    @model_validator(mode="after")
    def validate_identity(self) -> "AblationMetricDelta":
        left_present = self._validate_side(
            "left",
            self.left_metric_id,
            self.left_numerator,
            self.left_denominator,
        )
        right_present = self._validate_side(
            "right",
            self.right_metric_id,
            self.right_numerator,
            self.right_denominator,
        )
        expected_defined = bool(
            left_present
            and right_present
            and self.left_denominator > 0
            and self.right_denominator > 0
        )
        if self.defined is not expected_defined:
            raise ValueError("ablation delta defined state is inexact")
        expected = _canonical_hash(
            "ablation-metric-delta",
            {
                "defined": self.defined,
                "left_denominator": self.left_denominator,
                "left_metric_id": self.left_metric_id,
                "left_numerator": self.left_numerator,
                "right_denominator": self.right_denominator,
                "right_metric_id": self.right_metric_id,
                "right_numerator": self.right_numerator,
            },
        )
        if self.id != expected:
            raise ValueError("AblationMetricDelta ID is not deterministic")
        return self

    @staticmethod
    def _validate_side(
        label: str,
        metric_id: str | None,
        numerator: int | None,
        denominator: int | None,
    ) -> bool:
        values = (metric_id, numerator, denominator)
        if any(item is not None for item in values) and not all(
            item is not None for item in values
        ):
            raise ValueError(f"ablation delta {label} side must be all-or-none")
        if metric_id is None:
            return False
        if numerator < 0 or denominator < 0 or numerator > denominator:
            raise ValueError(
                f"ablation delta {label} side has invalid rational components"
            )
        return True

    @classmethod
    def create(
        cls,
        left: EvaluationMetricResult | ContextObjectiveUpperBoundRate | None,
        right: EvaluationMetricResult | ContextObjectiveUpperBoundRate | None,
    ) -> "AblationMetricDelta":
        defined = bool(left and right and left.defined and right.defined)
        payload = {
            "defined": defined,
            "left_denominator": left.denominator if left is not None else None,
            "left_metric_id": left.id if left is not None else None,
            "left_numerator": left.numerator if left is not None else None,
            "right_denominator": right.denominator if right is not None else None,
            "right_metric_id": right.id if right is not None else None,
            "right_numerator": right.numerator if right is not None else None,
        }
        return cls(id=_canonical_hash("ablation-metric-delta", payload), **payload)


class AblationComparisonReport(DomainModel):
    """Deterministic observed ablation comparison, never a causal estimate."""

    id: Identifier
    ablation_plan_id: Identifier
    benchmark_manifest_id: Identifier
    condition_results: list[AblationConditionResult]
    full_context_verification_hit_rate: EvaluationMetricResult | None = None
    masked_context_verification_hit_rate: EvaluationMetricResult | None = None
    no_model_verification_hit_rate: EvaluationMetricResult | None = None
    context_objective_upper_bound_rate: ContextObjectiveUpperBoundRate | None = None
    coverage_by_condition: dict[AblationConditionKind, EvaluationMetricResult]
    ground_truth_recall_by_condition: dict[
        AblationConditionKind, EvaluationMetricResult
    ]
    negative_false_positive_rate_by_condition: dict[
        AblationConditionKind, EvaluationMetricResult
    ]
    full_minus_masked_delta: AblationMetricDelta
    full_minus_no_model_delta: AblationMetricDelta
    upper_bound_minus_full_delta: AblationMetricDelta
    coverage_comparable: bool
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("condition_results")
    @classmethod
    def normalize_results(
        cls, values: list[AblationConditionResult]
    ) -> list[AblationConditionResult]:
        if len(values) != len({item.condition_kind for item in values}):
            raise ValueError("comparison condition results must be unique")
        return sorted(values, key=lambda item: item.condition_kind.value)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "AblationComparisonReport":
        if {item.condition_kind for item in self.condition_results} != set(
            AblationConditionKind
        ):
            raise ValueError("comparison requires all declared conditions")
        if any(
            item.ablation_plan_id != self.ablation_plan_id
            or item.benchmark_manifest_id != self.benchmark_manifest_id
            for item in self.condition_results
        ):
            raise ValueError("comparison condition binding mismatch")
        model_conditions = {
            AblationConditionKind.FULL_CONTEXT_MODEL,
            AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
            AblationConditionKind.NO_MODEL_BASELINE,
        }
        for mapping in (
            self.coverage_by_condition,
            self.ground_truth_recall_by_condition,
            self.negative_false_positive_rate_by_condition,
        ):
            if not set(mapping).issubset(model_conditions):
                raise ValueError("comparison metric map contains non-model condition")
        by_kind = {item.condition_kind: item for item in self.condition_results}
        reports = {
            kind: item.benchmark_evaluation_report
            for kind, item in by_kind.items()
            if item.benchmark_evaluation_report is not None
        }
        versions = {item.benchmark_version for item in reports.values()}
        runner_contracts = {item.runner_contract for item in reports.values()}
        upper = by_kind[
            AblationConditionKind.CONTEXT_OBJECTIVE_UPPER_BOUND
        ].context_objective_upper_bound_result
        if upper is not None:
            versions.add(upper.benchmark_version)
        if len(versions) > 1 or len(runner_contracts) > 1:
            raise ValueError("comparison children use incompatible benchmark contracts")
        expected_full = reports.get(
            AblationConditionKind.FULL_CONTEXT_MODEL
        )
        expected_masked = reports.get(
            AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
        )
        expected_no_model = reports.get(
            AblationConditionKind.NO_MODEL_BASELINE
        )
        expected_rates = (
            expected_full.verification_hit_rate if expected_full else None,
            expected_masked.verification_hit_rate if expected_masked else None,
            expected_no_model.verification_hit_rate if expected_no_model else None,
            upper.rate if upper else None,
        )
        if (
            self.full_context_verification_hit_rate,
            self.masked_context_verification_hit_rate,
            self.no_model_verification_hit_rate,
            self.context_objective_upper_bound_rate,
        ) != expected_rates:
            raise ValueError("comparison rates are not condition-derived")
        expected_coverage = {
            kind: report.primary_case_coverage for kind, report in reports.items()
        }
        expected_recall = {
            kind: report.ground_truth_chain_recall for kind, report in reports.items()
        }
        expected_negative = {
            kind: report.negative_control_false_positive_rate
            for kind, report in reports.items()
        }
        if (
            self.coverage_by_condition != expected_coverage
            or self.ground_truth_recall_by_condition != expected_recall
            or self.negative_false_positive_rate_by_condition
            != expected_negative
        ):
            raise ValueError("comparison metric maps are not condition-derived")
        expected_deltas = (
            AblationMetricDelta.create(expected_rates[0], expected_rates[1]),
            AblationMetricDelta.create(expected_rates[0], expected_rates[2]),
            AblationMetricDelta.create(expected_rates[3], expected_rates[0]),
        )
        if (
            self.full_minus_masked_delta,
            self.full_minus_no_model_delta,
            self.upper_bound_minus_full_delta,
        ) != expected_deltas:
            raise ValueError("comparison deltas are not metric-derived")
        coverage_metrics = list(expected_coverage.values())
        if upper is not None:
            coverage_metrics.append(upper.primary_case_coverage)
        expected_comparable = bool(
            len(expected_coverage) == 3
            and upper is not None
            and coverage_metrics
            and all(
                metric.numerator == metric.denominator
                and metric.denominator_ids
                == coverage_metrics[0].denominator_ids
                for metric in coverage_metrics
            )
        )
        if self.coverage_comparable is not expected_comparable:
            raise ValueError("coverage comparability is not cohort-derived")
        expected = _canonical_hash(
            "ablation-comparison-report",
            {
                "ablation_plan_id": self.ablation_plan_id,
                "benchmark_manifest_id": self.benchmark_manifest_id,
                "condition_result_ids": sorted(
                    item.id for item in self.condition_results
                ),
                "coverage_comparable": self.coverage_comparable,
                "delta_ids": sorted(
                    [
                        self.full_minus_masked_delta.id,
                        self.full_minus_no_model_delta.id,
                        self.upper_bound_minus_full_delta.id,
                    ]
                ),
                "metric_ids": sorted(
                    item.id
                    for item in (
                        self.full_context_verification_hit_rate,
                        self.masked_context_verification_hit_rate,
                        self.no_model_verification_hit_rate,
                        self.context_objective_upper_bound_rate,
                    )
                    if item is not None
                ),
                "coverage_metric_ids": sorted(
                    item.id for item in self.coverage_by_condition.values()
                ),
                "ground_truth_recall_metric_ids": sorted(
                    item.id for item in self.ground_truth_recall_by_condition.values()
                ),
                "negative_false_positive_metric_ids": sorted(
                    item.id
                    for item in self.negative_false_positive_rate_by_condition.values()
                ),
            },
        )
        if self.id != expected:
            raise ValueError("AblationComparisonReport ID is not deterministic")
        return self


def structured_prompt_sha256(values: dict[str, object]) -> str:
    """Hash bounded prompt fields without retaining prompt content in audits."""

    return hashlib.sha256(
        json.dumps(
            values,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
