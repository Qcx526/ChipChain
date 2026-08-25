"""Strict result contracts for candidate-side objective feasibility."""

from __future__ import annotations

import re

from pydantic import Field, field_validator, model_validator

from chipchain.evaluation.enums import (
    ChainFeasibilityReason,
    ChainFeasibilityStatus,
    ObjectiveFailureStage,
)
from chipchain.evaluation.models import _canonical_hash, _canonical_sha256
from chipchain.hardware_trigger.enums import TriggerabilityStatus
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.models.cross_layer import CrossLayerInteractionType
from chipchain.models.enums import Architecture


_FAILURE_CODE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|authorization|password|secret|token)\s*[:=]\s*\S+"
)
_SECRET_TOKEN = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")
_WINDOWS_ABSOLUTE_PATH = re.compile(
    r"(?i)(?:\b[A-Z]:[\\/]|(?<![\\\w])\\\\)[^\s\"']+"
)
_POSIX_ABSOLUTE_PATH = re.compile(
    r"(?<![:/\w.])/(?:[^/\s\"']+/)*[^/\s\"']+"
)
_HOME_RELATIVE_PATH = re.compile(r"(?<!\w)~(?:[\w.-]+)?[\\/][^\s\"']+")
_FILE_HOST_PATH = re.compile(r"(?i)\bfile://[^\s\"']+")
_TRACEBACK_PAYLOAD = re.compile(
    r"(?i)\b(?:backtrace|traceback|stack[\s_-]*trace)\b"
)
_STACK_FRAME_PAYLOAD = re.compile(
    r'(?im)(?:^|\n)\s*(?:File\s+"[^"\n]+",\s+line\s+\d+'
    r"|at\s+(?:[\w$<>]+\.)+[\w$<>]+\([^\n)]*\))"
)
_FORBIDDEN_FAILURE_METADATA_KEYS = {
    "apikey",
    "authorization",
    "hostpath",
    "providerkey",
    "rawstderr",
    "secret",
    "stacktrace",
    "stderr",
    "token",
    "traceback",
}
_SENSITIVE_FAILURE_METADATA_FRAGMENTS = (
    "apikey",
    "authorization",
    "hostpath",
    "providerkey",
    "secret",
    "stacktrace",
    "stderr",
    "token",
    "traceback",
)
_FORBIDDEN_ASSESSMENT_METADATA_KEYS = {
    "attackchain",
    "confidence",
    "coverage",
    "hitrate",
    "metricresult",
    "probability",
    "recall",
    "score",
    "feasibilitystatus",
    "verificationrecord",
    "verificationscore",
    "verificationstatus",
    "verified",
    "vulnerabilitystatus",
}


def objective_evaluation_failure_id(
    *,
    candidate_id: str,
    benchmark_case_id: str,
    architecture: Architecture,
    stage: ObjectiveFailureStage,
    failure_code: str,
) -> str:
    """Build failure identity without diagnostics, prose, or host state."""

    return _canonical_hash(
        "objective-evaluation-failure",
        {
            "architecture": Architecture(architecture).value,
            "benchmark_case_id": benchmark_case_id,
            "candidate_id": candidate_id,
            "failure_code": failure_code,
            "stage": ObjectiveFailureStage(stage).value,
        },
    )


def _validate_failure_metadata(metadata: Metadata) -> Metadata:
    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                normalized = "".join(
                    character
                    for character in str(key).lower()
                    if character.isalnum()
                )
                if normalized in _FORBIDDEN_FAILURE_METADATA_KEYS or any(
                    fragment in normalized
                    for fragment in _SENSITIVE_FAILURE_METADATA_FRAGMENTS
                ):
                    raise ValueError(
                        "objective failure metadata contains forbidden diagnostics"
                    )
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)
        elif isinstance(value, str):
            candidate = value.strip()
            if (
                _WINDOWS_ABSOLUTE_PATH.search(value)
                or _POSIX_ABSOLUTE_PATH.search(value)
                or _HOME_RELATIVE_PATH.search(value)
                or _FILE_HOST_PATH.search(value)
                or candidate.startswith(("/", "\\"))
                or candidate.lower().startswith("file:")
            ):
                raise ValueError(
                    "objective failure metadata must not contain host paths"
                )
            if (
                _SECRET_ASSIGNMENT.search(value)
                or _SECRET_TOKEN.search(value)
                or _TRACEBACK_PAYLOAD.search(value)
                or _STACK_FRAME_PAYLOAD.search(value)
            ):
                raise ValueError(
                    "objective failure metadata contains forbidden diagnostics"
                )

    visit(metadata)
    return metadata


def _validate_assessment_metadata(metadata: Metadata) -> Metadata:
    _validate_failure_metadata(metadata)

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                normalized = "".join(
                    character
                    for character in str(key).lower()
                    if character.isalnum()
                )
                if normalized in _FORBIDDEN_ASSESSMENT_METADATA_KEYS:
                    raise ValueError(
                        "assessment metadata must not contain verdict or metric fields"
                    )
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(metadata)
    return metadata


class ObjectiveEvaluationFailure(DomainModel):
    """Explicit bounded infrastructure failure, never a model/semantic outcome."""

    id: Identifier
    candidate_id: Identifier
    benchmark_case_id: Identifier
    architecture: Architecture
    stage: ObjectiveFailureStage
    failure_code: Identifier
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("failure_code", mode="before")
    @classmethod
    def validate_failure_code(cls, value: object) -> str:
        if not isinstance(value, str) or not _FAILURE_CODE.fullmatch(
            candidate := value.strip()
        ):
            raise ValueError(
                "objective failure code must be stable uppercase identifier text"
            )
        return candidate

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_failure_metadata(value)

    @model_validator(mode="after")
    def validate_scope_and_identity(self) -> "ObjectiveEvaluationFailure":
        if self.architecture is not Architecture.ARM:
            raise ValueError("Phase 10A objective failures support ARM only")
        expected_id = objective_evaluation_failure_id(
            candidate_id=self.candidate_id,
            benchmark_case_id=self.benchmark_case_id,
            architecture=self.architecture,
            stage=self.stage,
            failure_code=self.failure_code,
        )
        if self.id != expected_id:
            raise ValueError("ObjectiveEvaluationFailure ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        candidate_id: str,
        benchmark_case_id: str,
        architecture: Architecture | str,
        stage: ObjectiveFailureStage | str,
        failure_code: str,
        metadata: Metadata | None = None,
    ) -> "ObjectiveEvaluationFailure":
        """Create one path-neutral, deterministic infrastructure record."""

        normalized_architecture = Architecture(architecture)
        normalized_stage = ObjectiveFailureStage(stage)
        normalized_code = failure_code.strip()
        identity = objective_evaluation_failure_id(
            candidate_id=candidate_id,
            benchmark_case_id=benchmark_case_id,
            architecture=normalized_architecture,
            stage=normalized_stage,
            failure_code=normalized_code,
        )
        return cls(
            id=identity,
            candidate_id=candidate_id,
            benchmark_case_id=benchmark_case_id,
            architecture=normalized_architecture,
            stage=normalized_stage,
            failure_code=normalized_code,
            metadata=metadata or {},
        )


def _derived_assessment_semantics(
    *,
    interaction_type: CrossLayerInteractionType | None,
    triggerability_status: TriggerabilityStatus | None,
    infrastructure_failure_id: str | None,
) -> tuple[ChainFeasibilityStatus, list[ChainFeasibilityReason]]:
    if interaction_type is None:
        return (
            ChainFeasibilityStatus.UNRESOLVED,
            [ChainFeasibilityReason.CANDIDATE_TYPED_INTERACTION_MISSING],
        )
    if (
        interaction_type
        is CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
    ):
        return (
            ChainFeasibilityStatus.UNSUPPORTED,
            [
                ChainFeasibilityReason.TYPE_III_OBJECTIVE_PROPAGATION_NOT_IMPLEMENTED
            ],
        )
    if infrastructure_failure_id is not None:
        return (
            ChainFeasibilityStatus.INFRA_FAILURE,
            [ChainFeasibilityReason.OBJECTIVE_INFRASTRUCTURE_FAILURE],
        )
    if (
        interaction_type
        is CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE
    ):
        if triggerability_status is TriggerabilityStatus.NO_STATIC_TRIGGER_MATCH:
            return (
                ChainFeasibilityStatus.NOT_SUPPORTED,
                [ChainFeasibilityReason.NO_STATIC_TRIGGER_MATCH],
            )
        reasons = [
            ChainFeasibilityReason.TYPE_I_SOFTWARE_VULNERABILITY_TO_TRIGGER_LINK_NOT_IMPLEMENTED
        ]
        if triggerability_status is None:
            reasons.append(ChainFeasibilityReason.TRIGGERABILITY_RESULT_MISSING)
        elif triggerability_status is TriggerabilityStatus.NOT_OBSERVED_IN_RUNTIME:
            reasons.append(ChainFeasibilityReason.RUNTIME_TRIGGER_NOT_OBSERVED)
        elif (
            triggerability_status
            is TriggerabilityStatus.INSUFFICIENT_PRECONDITION_EVIDENCE
        ):
            reasons.append(
                ChainFeasibilityReason.PRECONDITION_EVIDENCE_INSUFFICIENT
            )
        return ChainFeasibilityStatus.UNRESOLVED, sorted(
            reasons, key=lambda item: item.value
        )
    if triggerability_status is None:
        return (
            ChainFeasibilityStatus.UNRESOLVED,
            [ChainFeasibilityReason.TRIGGERABILITY_RESULT_MISSING],
        )
    if triggerability_status is TriggerabilityStatus.TRIGGERABLE:
        return (
            ChainFeasibilityStatus.CONFIRMED_FEASIBLE,
            [ChainFeasibilityReason.TYPE_II_OBJECTIVELY_TRIGGERABLE],
        )
    if triggerability_status is TriggerabilityStatus.NO_STATIC_TRIGGER_MATCH:
        return (
            ChainFeasibilityStatus.NOT_SUPPORTED,
            [ChainFeasibilityReason.NO_STATIC_TRIGGER_MATCH],
        )
    if triggerability_status is TriggerabilityStatus.NOT_OBSERVED_IN_RUNTIME:
        return (
            ChainFeasibilityStatus.UNRESOLVED,
            [ChainFeasibilityReason.RUNTIME_TRIGGER_NOT_OBSERVED],
        )
    return (
        ChainFeasibilityStatus.UNRESOLVED,
        [ChainFeasibilityReason.PRECONDITION_EVIDENCE_INSUFFICIENT],
    )


def chain_feasibility_assessment_id(
    *,
    candidate_id: str,
    benchmark_case_id: str,
    architecture: Architecture,
    interaction_id: str | None,
    interaction_type: CrossLayerInteractionType | None,
    status: ChainFeasibilityStatus,
    reason_codes: list[ChainFeasibilityReason],
    artifact_id: str,
    artifact_sha256: str,
    triggerability_aggregation_id: str | None,
    triggerability_status: TriggerabilityStatus | None,
    infrastructure_failure_id: str | None,
    objective_component_ids: list[str],
) -> str:
    """Build assessment identity from objective result semantics only."""

    return _canonical_hash(
        "chain-feasibility-assessment",
        {
            "architecture": Architecture(architecture).value,
            "artifact_id": artifact_id,
            "artifact_sha256": _canonical_sha256(artifact_sha256),
            "benchmark_case_id": benchmark_case_id,
            "candidate_id": candidate_id,
            "infrastructure_failure_id": infrastructure_failure_id,
            "interaction_id": interaction_id,
            "interaction_type": (
                interaction_type.value if interaction_type is not None else None
            ),
            "objective_component_ids": sorted(objective_component_ids),
            "reason_codes": sorted(item.value for item in reason_codes),
            "status": ChainFeasibilityStatus(status).value,
            "triggerability_aggregation_id": triggerability_aggregation_id,
            "triggerability_status": (
                triggerability_status.value
                if triggerability_status is not None
                else None
            ),
        },
    )


class ChainFeasibilityAssessment(DomainModel):
    """One oracle-derived evaluation outcome, never a domain AttackChain."""

    id: Identifier
    candidate_id: Identifier
    benchmark_case_id: Identifier
    architecture: Architecture
    interaction_id: Identifier | None = None
    interaction_type: CrossLayerInteractionType | None = None
    status: ChainFeasibilityStatus
    reason_codes: list[ChainFeasibilityReason] = Field(min_length=1)
    artifact_id: Identifier
    artifact_sha256: Identifier
    triggerability_aggregation_id: Identifier | None = None
    triggerability_status: TriggerabilityStatus | None = None
    infrastructure_failure_id: Identifier | None = None
    objective_component_ids: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("artifact_sha256", mode="before")
    @classmethod
    def validate_sha256(cls, value: object) -> str:
        return _canonical_sha256(value)

    @field_validator("reason_codes")
    @classmethod
    def normalize_reason_codes(
        cls, values: list[ChainFeasibilityReason]
    ) -> list[ChainFeasibilityReason]:
        if len(values) != len(set(values)):
            raise ValueError("chain feasibility reason codes must be unique")
        return sorted(values, key=lambda item: item.value)

    @field_validator("objective_component_ids")
    @classmethod
    def normalize_component_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("objective component IDs must be unique")
        return sorted(values)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_assessment_metadata(value)

    @model_validator(mode="after")
    def validate_shape_and_identity(self) -> "ChainFeasibilityAssessment":
        if self.architecture is not Architecture.ARM:
            raise ValueError("Phase 10A chain feasibility supports ARM only")
        if (self.interaction_id is None) != (self.interaction_type is None):
            raise ValueError("assessment interaction identity/type are all-or-none")
        if (self.triggerability_aggregation_id is None) != (
            self.triggerability_status is None
        ):
            raise ValueError(
                "assessment triggerability identity/status are all-or-none"
            )
        if (
            self.infrastructure_failure_id is not None
            and self.triggerability_aggregation_id is not None
        ):
            raise ValueError(
                "assessment cannot combine a completed triggerability result "
                "with infrastructure failure"
            )
        if self.interaction_type is None and (
            self.triggerability_aggregation_id is not None
            or self.infrastructure_failure_id is not None
        ):
            raise ValueError(
                "untyped assessment cannot contain objective interaction results"
            )
        if (
            self.interaction_type
            is CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
            and (
                self.triggerability_aggregation_id is not None
                or self.infrastructure_failure_id is not None
            )
        ):
            raise ValueError(
                "Type III assessment cannot contain software-to-hardware results"
            )
        expected_components = sorted(
            item
            for item in (
                self.interaction_id,
                self.triggerability_aggregation_id,
                self.infrastructure_failure_id,
            )
            if item is not None
        )
        if self.objective_component_ids != expected_components:
            raise ValueError("assessment objective component IDs are not exact")
        expected_status, expected_reasons = _derived_assessment_semantics(
            interaction_type=self.interaction_type,
            triggerability_status=self.triggerability_status,
            infrastructure_failure_id=self.infrastructure_failure_id,
        )
        if self.status is not expected_status or self.reason_codes != expected_reasons:
            raise ValueError("chain feasibility status/reasons are not oracle-derived")
        expected_id = chain_feasibility_assessment_id(
            candidate_id=self.candidate_id,
            benchmark_case_id=self.benchmark_case_id,
            architecture=self.architecture,
            interaction_id=self.interaction_id,
            interaction_type=self.interaction_type,
            status=self.status,
            reason_codes=self.reason_codes,
            artifact_id=self.artifact_id,
            artifact_sha256=self.artifact_sha256,
            triggerability_aggregation_id=self.triggerability_aggregation_id,
            triggerability_status=self.triggerability_status,
            infrastructure_failure_id=self.infrastructure_failure_id,
            objective_component_ids=self.objective_component_ids,
        )
        if self.id != expected_id:
            raise ValueError("ChainFeasibilityAssessment ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        candidate_id: str,
        benchmark_case_id: str,
        architecture: Architecture,
        interaction_id: str | None,
        interaction_type: CrossLayerInteractionType | None,
        artifact_id: str,
        artifact_sha256: str,
        triggerability_aggregation_id: str | None = None,
        triggerability_status: TriggerabilityStatus | None = None,
        infrastructure_failure_id: str | None = None,
        metadata: Metadata | None = None,
    ) -> "ChainFeasibilityAssessment":
        """Derive status, reasons, components, and identity from bound facts."""

        status, reasons = _derived_assessment_semantics(
            interaction_type=interaction_type,
            triggerability_status=triggerability_status,
            infrastructure_failure_id=infrastructure_failure_id,
        )
        components = sorted(
            item
            for item in (
                interaction_id,
                triggerability_aggregation_id,
                infrastructure_failure_id,
            )
            if item is not None
        )
        identity = chain_feasibility_assessment_id(
            candidate_id=candidate_id,
            benchmark_case_id=benchmark_case_id,
            architecture=architecture,
            interaction_id=interaction_id,
            interaction_type=interaction_type,
            status=status,
            reason_codes=reasons,
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            triggerability_aggregation_id=triggerability_aggregation_id,
            triggerability_status=triggerability_status,
            infrastructure_failure_id=infrastructure_failure_id,
            objective_component_ids=components,
        )
        return cls(
            id=identity,
            candidate_id=candidate_id,
            benchmark_case_id=benchmark_case_id,
            architecture=architecture,
            interaction_id=interaction_id,
            interaction_type=interaction_type,
            status=status,
            reason_codes=reasons,
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            triggerability_aggregation_id=triggerability_aggregation_id,
            triggerability_status=triggerability_status,
            infrastructure_failure_id=infrastructure_failure_id,
            objective_component_ids=components,
            metadata=metadata or {},
        )
