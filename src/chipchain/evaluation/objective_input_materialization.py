"""Offline Phase 10D objective triggerability input materialization."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath

from chipchain.analysis.models import ProgramArtifact
from chipchain.evaluation.execution_models import (
    RealExperimentCaseInput,
    RealExperimentInputSet,
)
from chipchain.evaluation.experiment_models import RealModelExperimentPlan
from chipchain.evaluation.objective_input_models import (
    ObjectiveExperimentCaseSource,
    ObjectiveExperimentInputSourceSet,
    ObjectiveTriggerabilityMaterializationRecord,
)
from chipchain.hardware_trigger import (
    AngrFirmwareTriggerMatcher,
    FirmwareTriggerMatcher,
    HardwareTriggerSignature,
    RuntimeFirmwareTriggerMatcher,
    TriggerabilityAggregator,
)
from chipchain.runtime.qemu import (
    QemuTriggerRawTraceParser,
    normalize_qemu_trigger_trace,
)


class ObjectiveInputMaterializationError(ValueError):
    """Fail-closed error while materializing candidate-side objective facts."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ObjectiveInputMaterializationError(
            "objective source file could not be hashed"
        ) from exc
    return digest.hexdigest()


def _resolve_source_file(fixture_root: Path, logical_reference: str) -> Path:
    try:
        root = fixture_root.resolve(strict=True)
    except OSError as exc:
        raise ObjectiveInputMaterializationError(
            "objective fixture root does not exist"
        ) from exc
    if not root.is_dir():
        raise ObjectiveInputMaterializationError(
            "objective fixture root must be a directory"
        )
    candidate = root.joinpath(*PurePosixPath(logical_reference).parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ObjectiveInputMaterializationError(
            "objective source file does not exist"
        ) from exc
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ObjectiveInputMaterializationError(
            "objective source file escapes fixture root"
        )
    return resolved


class Phase10DObjectiveInputMaterializer:
    """Compose frozen candidate-side files through existing Phase 9C APIs."""

    def __init__(
        self,
        *,
        static_matcher: FirmwareTriggerMatcher | None = None,
        raw_parser: QemuTriggerRawTraceParser | None = None,
        runtime_matcher: RuntimeFirmwareTriggerMatcher | None = None,
        aggregator: TriggerabilityAggregator | None = None,
    ) -> None:
        self._static_matcher = static_matcher or AngrFirmwareTriggerMatcher()
        self._raw_parser = raw_parser or QemuTriggerRawTraceParser()
        self._runtime_matcher = runtime_matcher or RuntimeFirmwareTriggerMatcher()
        self._aggregator = aggregator or TriggerabilityAggregator()

    def materialize_case_input(
        self,
        plan: RealModelExperimentPlan,
        case_source: ObjectiveExperimentCaseSource,
        *,
        fixture_root: str | Path,
    ) -> RealExperimentCaseInput:
        """Build one persistent case input without QEMU, provider, or truth data."""

        if not isinstance(plan, RealModelExperimentPlan):
            raise TypeError("objective materialization requires experiment plan")
        if not isinstance(case_source, ObjectiveExperimentCaseSource):
            raise TypeError("objective materialization requires case source")
        plan_snapshot = RealModelExperimentPlan.model_validate(
            plan.model_dump(mode="json")
        )
        detached = ObjectiveExperimentCaseSource.model_validate(
            case_source.model_dump(mode="json")
        )
        if detached.benchmark_case_id not in plan_snapshot.case_ids:
            raise ObjectiveInputMaterializationError(
                "objective source case is outside experiment plan"
            )
        source = detached.triggerability_source
        if source is None:
            return RealExperimentCaseInput.create(
                plan_snapshot,
                benchmark_case_id=detached.benchmark_case_id,
                reasoning_context=detached.reasoning_context,
            )

        root = Path(fixture_root)
        artifact_path = _resolve_source_file(root, source.artifact_reference)
        signature_path = _resolve_source_file(root, source.signature_reference)
        raw_trace_path = _resolve_source_file(root, source.raw_trace_reference)

        artifact_sha256 = _sha256_file(artifact_path)
        if artifact_sha256 != source.expected_artifact_sha256:
            raise ObjectiveInputMaterializationError(
                "objective artifact SHA-256 mismatch"
            )
        signature_file_sha256 = _sha256_file(signature_path)
        if signature_file_sha256 != source.expected_signature_file_sha256:
            raise ObjectiveInputMaterializationError(
                "objective signature file SHA-256 mismatch"
            )
        raw_trace_sha256 = _sha256_file(raw_trace_path)
        if raw_trace_sha256 != source.expected_raw_trace_sha256:
            raise ObjectiveInputMaterializationError(
                "objective raw trace SHA-256 mismatch"
            )

        try:
            signature = HardwareTriggerSignature.model_validate_json(
                signature_path.read_bytes()
            )
        except (OSError, TypeError, ValueError) as exc:
            raise ObjectiveInputMaterializationError(
                "objective signature contract is invalid"
            ) from exc
        if signature.id != source.expected_signature_id:
            raise ObjectiveInputMaterializationError(
                "objective signature semantic ID mismatch"
            )
        if (
            signature.hardware_vulnerability_id,
            signature.architecture,
            signature.execution_mode,
        ) != (
            source.hardware_vulnerability_id,
            source.architecture,
            source.execution_mode,
        ):
            raise ObjectiveInputMaterializationError(
                "objective signature source binding mismatch"
            )

        artifact = ProgramArtifact(
            id=source.artifact_id,
            architecture=source.architecture,
            artifact_type=source.artifact_type,
            path=str(artifact_path),
            fixture_identifier=source.id,
            metadata={
                "owned": source.owned,
                "synthetic": source.synthetic,
                "not_real_vulnerability": source.not_real_vulnerability,
            },
        )
        static_result = self._static_matcher.match(artifact, signature)
        if (
            static_result.artifact_id,
            static_result.artifact_sha256,
            static_result.signature_id,
            static_result.hardware_vulnerability_id,
            static_result.architecture,
            static_result.execution_mode,
        ) != (
            source.artifact_id,
            source.expected_artifact_sha256,
            source.expected_signature_id,
            source.hardware_vulnerability_id,
            source.architecture,
            source.execution_mode,
        ):
            raise ObjectiveInputMaterializationError(
                "objective static result source binding mismatch"
            )

        parsed = self._raw_parser.parse(raw_trace_path)
        if parsed.raw_trace_sha256 != source.expected_raw_trace_sha256:
            raise ObjectiveInputMaterializationError(
                "parsed objective raw trace SHA-256 mismatch"
            )
        if parsed.header.run_id != source.expected_run_id:
            raise ObjectiveInputMaterializationError(
                "objective raw trace run ID mismatch"
            )
        runtime_trace = normalize_qemu_trigger_trace(
            parsed,
            run_id=source.expected_run_id,
            scenario_id=source.scenario_id,
            artifact_id=source.artifact_id,
            artifact_sha256=source.expected_artifact_sha256,
        )
        runtime_result = self._runtime_matcher.match(
            static_result, runtime_trace
        )
        aggregation = self._aggregator.aggregate(
            signature, static_result, runtime_result
        )
        if (
            aggregation.signature_id,
            aggregation.hardware_vulnerability_id,
            aggregation.architecture,
            aggregation.execution_mode,
            aggregation.artifact_id,
            aggregation.artifact_sha256,
            aggregation.trace_id,
            aggregation.raw_trace_sha256,
        ) != (
            source.expected_signature_id,
            source.hardware_vulnerability_id,
            source.architecture,
            source.execution_mode,
            source.artifact_id,
            source.expected_artifact_sha256,
            runtime_trace.id,
            source.expected_raw_trace_sha256,
        ):
            raise ObjectiveInputMaterializationError(
                "objective aggregation source binding mismatch"
            )

        record = ObjectiveTriggerabilityMaterializationRecord.create(
            source=source,
            reasoning_context_id=detached.reasoning_context.id,
            artifact_sha256=artifact_sha256,
            signature_file_sha256=signature_file_sha256,
            signature_id=signature.id,
            raw_trace_sha256=parsed.raw_trace_sha256,
            parsed_raw_trace_id=parsed.id,
            runtime_trace_id=runtime_trace.id,
            static_result_sha256=aggregation.static_result_sha256,
            runtime_result_sha256=aggregation.runtime_result_sha256,
            triggerability_aggregation_id=aggregation.id,
            static_match_ids=[item.id for item in static_result.matches],
            runtime_occurrence_ids=[
                item.id for item in runtime_result.occurrences
            ],
        )
        return RealExperimentCaseInput.create(
            plan_snapshot,
            benchmark_case_id=detached.benchmark_case_id,
            reasoning_context=detached.reasoning_context,
            triggerability=aggregation,
            objective_materialization=record,
        )

    def materialize_input_set(
        self,
        plan: RealModelExperimentPlan,
        source_set: ObjectiveExperimentInputSourceSet,
        *,
        fixture_root: str | Path,
    ) -> RealExperimentInputSet:
        """Materialize the exact frozen case cohort into one detached input set."""

        if not isinstance(source_set, ObjectiveExperimentInputSourceSet):
            raise TypeError("objective materialization requires source set")
        detached = ObjectiveExperimentInputSourceSet.model_validate(
            source_set.model_dump(mode="json")
        )
        if {item.benchmark_case_id for item in detached.case_sources} != set(
            plan.case_ids
        ):
            raise ObjectiveInputMaterializationError(
                "objective source cohort does not match experiment plan"
            )
        case_inputs = [
            self.materialize_case_input(
                plan, item, fixture_root=fixture_root
            )
            for item in detached.case_sources
        ]
        return RealExperimentInputSet.create(plan, case_inputs=case_inputs)
