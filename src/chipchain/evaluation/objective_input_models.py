"""Ground-Truth-free Phase 10D objective-input provenance contracts."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.agents.base import ReasoningContext
from chipchain.hardware_trigger.enums import ArmExecutionMode
from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[/\\]")


def _canonical_id(prefix: str, payload: object) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(serialized).hexdigest()}"


def _canonical_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value.strip()):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value.strip()


def _logical_reference(value: object) -> str:
    if not isinstance(value, str) or not (candidate := value.strip()):
        raise ValueError("logical reference must be non-empty text")
    path = PurePosixPath(candidate)
    if (
        path.is_absolute()
        or candidate.startswith(("~", "\\"))
        or _WINDOWS_ABSOLUTE.match(candidate)
        or "\\" in candidate
        or ".." in path.parts
        or "." in path.parts
    ):
        raise ValueError("logical reference must be relative and path-neutral")
    return path.as_posix()


def objective_triggerability_source_id(
    *,
    benchmark_case_id: str,
    architecture: Architecture,
    execution_mode: ArmExecutionMode,
    candidate_interaction_id: str,
    hardware_vulnerability_id: str,
    artifact_id: str,
    artifact_type: str,
    artifact_reference: str,
    expected_artifact_sha256: str,
    signature_reference: str,
    expected_signature_file_sha256: str,
    expected_signature_id: str,
    raw_trace_reference: str,
    expected_raw_trace_sha256: str,
    expected_run_id: str,
    scenario_id: str,
    owned: bool,
    synthetic: bool,
    not_real_vulnerability: bool,
) -> str:
    """Build a host-path- and outcome-neutral source identity."""

    return _canonical_id(
        "objective-triggerability-source",
        {
            "architecture": Architecture(architecture).value,
            "artifact_id": artifact_id,
            "artifact_reference": artifact_reference,
            "artifact_type": artifact_type,
            "benchmark_case_id": benchmark_case_id,
            "candidate_interaction_id": candidate_interaction_id,
            "execution_mode": ArmExecutionMode(execution_mode).value,
            "expected_artifact_sha256": expected_artifact_sha256,
            "expected_raw_trace_sha256": expected_raw_trace_sha256,
            "expected_run_id": expected_run_id,
            "expected_signature_file_sha256": expected_signature_file_sha256,
            "expected_signature_id": expected_signature_id,
            "hardware_vulnerability_id": hardware_vulnerability_id,
            "not_real_vulnerability": not_real_vulnerability,
            "owned": owned,
            "raw_trace_reference": raw_trace_reference,
            "scenario_id": scenario_id,
            "signature_reference": signature_reference,
            "synthetic": synthetic,
        },
    )


class ObjectiveTriggerabilitySource(DomainModel):
    """Candidate-side files and declarations used for objective replay."""

    id: Identifier
    benchmark_case_id: Identifier
    architecture: Architecture
    execution_mode: ArmExecutionMode
    candidate_interaction_id: Identifier
    hardware_vulnerability_id: Identifier
    artifact_id: Identifier
    artifact_type: Literal["elf"]
    artifact_reference: Identifier
    expected_artifact_sha256: Identifier
    signature_reference: Identifier
    expected_signature_file_sha256: Identifier
    expected_signature_id: Identifier
    raw_trace_reference: Identifier
    expected_raw_trace_sha256: Identifier
    expected_run_id: Identifier
    scenario_id: Identifier
    owned: Literal[True]
    synthetic: Literal[True]
    not_real_vulnerability: Literal[True]

    @field_validator(
        "artifact_reference",
        "signature_reference",
        "raw_trace_reference",
        mode="before",
    )
    @classmethod
    def validate_logical_reference(cls, value: object) -> str:
        return _logical_reference(value)

    @field_validator(
        "expected_artifact_sha256",
        "expected_signature_file_sha256",
        "expected_raw_trace_sha256",
        mode="before",
    )
    @classmethod
    def validate_sha256(cls, value: object, info) -> str:
        return _canonical_sha256(value, label=info.field_name)

    @model_validator(mode="after")
    def validate_scope_and_identity(self) -> "ObjectiveTriggerabilitySource":
        if self.architecture is not Architecture.ARM:
            raise ValueError("objective triggerability sources support ARM only")
        if self.execution_mode is not ArmExecutionMode.A32:
            raise ValueError("objective triggerability sources support A32 only")
        expected = objective_triggerability_source_id(
            **self.model_dump(mode="python", exclude={"id"})
        )
        if self.id != expected:
            raise ValueError("ObjectiveTriggerabilitySource ID is not deterministic")
        return self

    @classmethod
    def create(cls, **values: object) -> "ObjectiveTriggerabilitySource":
        """Create one source without any expected status or output identity."""

        data = dict(values)
        data["architecture"] = Architecture(data["architecture"])
        data["execution_mode"] = ArmExecutionMode(data["execution_mode"])
        for field_name in (
            "artifact_reference",
            "signature_reference",
            "raw_trace_reference",
        ):
            data[field_name] = _logical_reference(data[field_name])
        for field_name in (
            "expected_artifact_sha256",
            "expected_signature_file_sha256",
            "expected_raw_trace_sha256",
        ):
            data[field_name] = _canonical_sha256(
                data[field_name], label=field_name
            )
        identity = objective_triggerability_source_id(**data)
        return cls(id=identity, **data)


def objective_materialization_record_id(
    *,
    source_id: str,
    reasoning_context_id: str,
    artifact_sha256: str,
    signature_file_sha256: str,
    signature_id: str,
    raw_trace_sha256: str,
    parsed_raw_trace_id: str,
    runtime_trace_id: str,
    static_result_sha256: str,
    runtime_result_sha256: str,
    triggerability_aggregation_id: str,
    static_match_ids: list[str],
    runtime_occurrence_ids: list[str],
) -> str:
    """Bind the declared source to exact derived production provenance."""

    return _canonical_id(
        "objective-triggerability-materialization",
        {
            "artifact_sha256": artifact_sha256,
            "parsed_raw_trace_id": parsed_raw_trace_id,
            "raw_trace_sha256": raw_trace_sha256,
            "reasoning_context_id": reasoning_context_id,
            "runtime_occurrence_ids": sorted(runtime_occurrence_ids),
            "runtime_result_sha256": runtime_result_sha256,
            "runtime_trace_id": runtime_trace_id,
            "signature_file_sha256": signature_file_sha256,
            "signature_id": signature_id,
            "source_id": source_id,
            "static_match_ids": sorted(static_match_ids),
            "static_result_sha256": static_result_sha256,
            "triggerability_aggregation_id": triggerability_aggregation_id,
        },
    )


class ObjectiveTriggerabilityMaterializationRecord(DomainModel):
    """Persistent bounded provenance for one production materialization."""

    id: Identifier
    source: ObjectiveTriggerabilitySource
    reasoning_context_id: Identifier
    artifact_sha256: Identifier
    signature_file_sha256: Identifier
    signature_id: Identifier
    raw_trace_sha256: Identifier
    parsed_raw_trace_id: Identifier
    runtime_trace_id: Identifier
    static_result_sha256: Identifier
    runtime_result_sha256: Identifier
    triggerability_aggregation_id: Identifier
    static_match_ids: list[Identifier] = Field(default_factory=list)
    runtime_occurrence_ids: list[Identifier] = Field(default_factory=list)

    @field_validator("source")
    @classmethod
    def snapshot_source(
        cls, value: ObjectiveTriggerabilitySource
    ) -> ObjectiveTriggerabilitySource:
        return ObjectiveTriggerabilitySource.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator(
        "artifact_sha256",
        "signature_file_sha256",
        "raw_trace_sha256",
        "static_result_sha256",
        "runtime_result_sha256",
        mode="before",
    )
    @classmethod
    def validate_sha256(cls, value: object, info) -> str:
        return _canonical_sha256(value, label=info.field_name)

    @field_validator("static_match_ids", "runtime_occurrence_ids")
    @classmethod
    def normalize_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("materialization derived IDs must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_source_binding_and_identity(
        self,
    ) -> "ObjectiveTriggerabilityMaterializationRecord":
        if (
            self.artifact_sha256,
            self.signature_file_sha256,
            self.signature_id,
            self.raw_trace_sha256,
        ) != (
            self.source.expected_artifact_sha256,
            self.source.expected_signature_file_sha256,
            self.source.expected_signature_id,
            self.source.expected_raw_trace_sha256,
        ):
            raise ValueError("materialization hashes do not match source declaration")
        expected = objective_materialization_record_id(
            source_id=self.source.id,
            reasoning_context_id=self.reasoning_context_id,
            artifact_sha256=self.artifact_sha256,
            signature_file_sha256=self.signature_file_sha256,
            signature_id=self.signature_id,
            raw_trace_sha256=self.raw_trace_sha256,
            parsed_raw_trace_id=self.parsed_raw_trace_id,
            runtime_trace_id=self.runtime_trace_id,
            static_result_sha256=self.static_result_sha256,
            runtime_result_sha256=self.runtime_result_sha256,
            triggerability_aggregation_id=self.triggerability_aggregation_id,
            static_match_ids=self.static_match_ids,
            runtime_occurrence_ids=self.runtime_occurrence_ids,
        )
        if self.id != expected:
            raise ValueError(
                "ObjectiveTriggerabilityMaterializationRecord ID is not deterministic"
            )
        return self

    @classmethod
    def create(cls, **values: object) -> "ObjectiveTriggerabilityMaterializationRecord":
        data = dict(values)
        source = ObjectiveTriggerabilitySource.model_validate(
            data["source"].model_dump(mode="json")
            if isinstance(data["source"], ObjectiveTriggerabilitySource)
            else data["source"]
        )
        data["source"] = source
        data["static_match_ids"] = sorted(data.get("static_match_ids", []))
        data["runtime_occurrence_ids"] = sorted(
            data.get("runtime_occurrence_ids", [])
        )
        identity = objective_materialization_record_id(
            source_id=source.id,
            reasoning_context_id=str(data["reasoning_context_id"]),
            artifact_sha256=str(data["artifact_sha256"]),
            signature_file_sha256=str(data["signature_file_sha256"]),
            signature_id=str(data["signature_id"]),
            raw_trace_sha256=str(data["raw_trace_sha256"]),
            parsed_raw_trace_id=str(data["parsed_raw_trace_id"]),
            runtime_trace_id=str(data["runtime_trace_id"]),
            static_result_sha256=str(data["static_result_sha256"]),
            runtime_result_sha256=str(data["runtime_result_sha256"]),
            triggerability_aggregation_id=str(
                data["triggerability_aggregation_id"]
            ),
            static_match_ids=list(data["static_match_ids"]),
            runtime_occurrence_ids=list(data["runtime_occurrence_ids"]),
        )
        return cls(id=identity, **data)


def objective_experiment_case_source_id(
    *,
    benchmark_case_id: str,
    reasoning_context_id: str,
    triggerability_source_id: str | None,
) -> str:
    return _canonical_id(
        "objective-experiment-case-source",
        {
            "benchmark_case_id": benchmark_case_id,
            "reasoning_context_id": reasoning_context_id,
            "triggerability_source_id": triggerability_source_id,
        },
    )


class ObjectiveExperimentCaseSource(DomainModel):
    """One candidate-side context and its optional objective replay source."""

    id: Identifier
    benchmark_case_id: Identifier
    reasoning_context: ReasoningContext
    triggerability_source: ObjectiveTriggerabilitySource | None = None

    @field_validator("reasoning_context")
    @classmethod
    def snapshot_context(cls, value: ReasoningContext) -> ReasoningContext:
        return ReasoningContext.model_validate(value.model_dump(mode="json"))

    @field_validator("triggerability_source")
    @classmethod
    def snapshot_triggerability_source(
        cls, value: ObjectiveTriggerabilitySource | None
    ) -> ObjectiveTriggerabilitySource | None:
        if value is None:
            return None
        return ObjectiveTriggerabilitySource.model_validate(
            value.model_dump(mode="json")
        )

    @model_validator(mode="after")
    def validate_binding_and_identity(self) -> "ObjectiveExperimentCaseSource":
        source = self.triggerability_source
        if source is not None:
            interaction = self.reasoning_context.cross_layer_interaction
            if source.benchmark_case_id != self.benchmark_case_id:
                raise ValueError("objective source benchmark case mismatch")
            if source.architecture is not self.reasoning_context.architecture:
                raise ValueError("objective source context architecture mismatch")
            if interaction is None or source.candidate_interaction_id != interaction.id:
                raise ValueError("objective source context interaction mismatch")
            if source.hardware_vulnerability_id not in (
                interaction.target_vulnerability_ids
            ):
                raise ValueError("objective source hardware target mismatch")
        expected = objective_experiment_case_source_id(
            benchmark_case_id=self.benchmark_case_id,
            reasoning_context_id=self.reasoning_context.id,
            triggerability_source_id=source.id if source is not None else None,
        )
        if self.id != expected:
            raise ValueError("ObjectiveExperimentCaseSource ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        benchmark_case_id: str,
        reasoning_context: ReasoningContext,
        triggerability_source: ObjectiveTriggerabilitySource | None = None,
    ) -> "ObjectiveExperimentCaseSource":
        context = ReasoningContext.model_validate(
            reasoning_context.model_dump(mode="json")
        )
        source = (
            ObjectiveTriggerabilitySource.model_validate(
                triggerability_source.model_dump(mode="json")
            )
            if triggerability_source is not None
            else None
        )
        case_id = benchmark_case_id.strip()
        identity = objective_experiment_case_source_id(
            benchmark_case_id=case_id,
            reasoning_context_id=context.id,
            triggerability_source_id=source.id if source is not None else None,
        )
        return cls(
            id=identity,
            benchmark_case_id=case_id,
            reasoning_context=context,
            triggerability_source=source,
        )


PHASE10D_OBJECTIVE_INPUT_SOURCE_CONTRACT = (
    "phase10d_objective_input_source_v1"
)


def objective_experiment_input_source_set_id(
    *, contract: str, case_source_ids: list[str]
) -> str:
    return _canonical_id(
        "objective-experiment-input-source-set",
        {
            "case_source_ids": sorted(case_source_ids),
            "contract": contract,
        },
    )


class ObjectiveExperimentInputSourceSet(DomainModel):
    """Complete candidate-side source cohort with no outcome declarations."""

    id: Identifier
    contract: Literal["phase10d_objective_input_source_v1"]
    case_sources: list[ObjectiveExperimentCaseSource] = Field(min_length=1)

    @field_validator("case_sources")
    @classmethod
    def normalize_case_sources(
        cls, values: list[ObjectiveExperimentCaseSource]
    ) -> list[ObjectiveExperimentCaseSource]:
        snapshots = [
            ObjectiveExperimentCaseSource.model_validate(
                item.model_dump(mode="json")
            )
            for item in values
        ]
        if len(snapshots) != len({item.id for item in snapshots}):
            raise ValueError("objective case source IDs must be unique")
        if len(snapshots) != len(
            {item.benchmark_case_id for item in snapshots}
        ):
            raise ValueError("objective benchmark case IDs must be unique")
        return sorted(snapshots, key=lambda item: item.benchmark_case_id)

    @model_validator(mode="after")
    def validate_identity(self) -> "ObjectiveExperimentInputSourceSet":
        expected = objective_experiment_input_source_set_id(
            contract=self.contract,
            case_source_ids=[item.id for item in self.case_sources],
        )
        if self.id != expected:
            raise ValueError(
                "ObjectiveExperimentInputSourceSet ID is not deterministic"
            )
        return self

    @classmethod
    def create(
        cls, *, case_sources: list[ObjectiveExperimentCaseSource]
    ) -> "ObjectiveExperimentInputSourceSet":
        snapshots = [
            ObjectiveExperimentCaseSource.model_validate(
                item.model_dump(mode="json")
            )
            for item in case_sources
        ]
        identity = objective_experiment_input_source_set_id(
            contract=PHASE10D_OBJECTIVE_INPUT_SOURCE_CONTRACT,
            case_source_ids=[item.id for item in snapshots],
        )
        return cls(
            id=identity,
            contract=PHASE10D_OBJECTIVE_INPUT_SOURCE_CONTRACT,
            case_sources=snapshots,
        )
