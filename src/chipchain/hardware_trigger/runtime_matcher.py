"""Exact contiguous PC-and-word matching for Phase 9C Step 3A."""

from __future__ import annotations

from pydantic import ValidationError

from chipchain.hardware_trigger.errors import (
    InvalidRuntimeTriggerInputError,
    RuntimeTriggerBindingError,
)
from chipchain.hardware_trigger.runtime_models import (
    RuntimeFirmwareTriggerMatchResult,
    RuntimeFirmwareTriggerOccurrence,
    RuntimeTriggerExecutionTrace,
    static_trigger_result_sha256,
)
from chipchain.hardware_trigger.static_models import StaticFirmwareTriggerMatchResult
from chipchain.models.enums import Architecture


class RuntimeFirmwareTriggerMatcher:
    """Confirm only exact T execution in one concrete normalized trace."""

    def match(
        self,
        static_result: StaticFirmwareTriggerMatchResult,
        runtime_trace: RuntimeTriggerExecutionTrace,
    ) -> RuntimeFirmwareTriggerMatchResult:
        """Detached-revalidate inputs and match consecutive ``(PC, word)`` pairs."""

        if not isinstance(static_result, StaticFirmwareTriggerMatchResult):
            raise InvalidRuntimeTriggerInputError(
                "runtime matching requires StaticFirmwareTriggerMatchResult"
            )
        if not isinstance(runtime_trace, RuntimeTriggerExecutionTrace):
            raise InvalidRuntimeTriggerInputError(
                "runtime matching requires RuntimeTriggerExecutionTrace"
            )
        try:
            static = StaticFirmwareTriggerMatchResult.model_validate(
                static_result.model_dump(mode="json")
            )
            runtime = RuntimeTriggerExecutionTrace.model_validate(
                runtime_trace.model_dump(mode="json")
            )
        except ValidationError as exc:
            raise InvalidRuntimeTriggerInputError(
                "runtime trigger inputs failed detached revalidation"
            ) from exc
        if static.architecture is not Architecture.ARM or (
            runtime.architecture is not Architecture.ARM
        ):
            raise InvalidRuntimeTriggerInputError(
                "runtime trigger matching supports ARM only"
            )
        if static.architecture is not runtime.architecture or (
            static.execution_mode is not runtime.execution_mode
        ):
            raise RuntimeTriggerBindingError(
                "static and runtime trigger architecture/mode mismatch"
            )
        if static.artifact_id != runtime.artifact_id:
            raise RuntimeTriggerBindingError(
                "static and runtime trigger artifact ID mismatch"
            )
        if static.artifact_sha256 != runtime.artifact_sha256:
            raise RuntimeTriggerBindingError(
                "static and runtime trigger firmware SHA-256 mismatch"
            )

        occurrences: list[RuntimeFirmwareTriggerOccurrence] = []
        for static_match in static.matches:
            expected = [
                (item.instruction_address, item.instruction_word)
                for item in static_match.instruction_locations
            ]
            width = len(expected)
            for start in range(0, len(runtime.instructions) - width + 1):
                candidate = runtime.instructions[start : start + width]
                actual = [(item.pc, item.instruction_word) for item in candidate]
                if actual != expected:
                    continue
                occurrences.append(
                    RuntimeFirmwareTriggerOccurrence.create(
                        trace_id=runtime.id,
                        raw_trace_sha256=runtime.raw_trace_sha256,
                        artifact_id=runtime.artifact_id,
                        artifact_sha256=runtime.artifact_sha256,
                        static_match_id=static_match.id,
                        signature_id=static.signature_id,
                        hardware_vulnerability_id=static.hardware_vulnerability_id,
                        architecture=runtime.architecture,
                        execution_mode=runtime.execution_mode,
                        instructions=candidate,
                        metadata={"observation_scope": "exact_runtime_sequence_t_only"},
                    )
                )

        return RuntimeFirmwareTriggerMatchResult(
            trace_id=runtime.id,
            raw_trace_sha256=runtime.raw_trace_sha256,
            artifact_id=runtime.artifact_id,
            artifact_sha256=runtime.artifact_sha256,
            static_result_sha256=static_trigger_result_sha256(static),
            signature_id=static.signature_id,
            hardware_vulnerability_id=static.hardware_vulnerability_id,
            architecture=runtime.architecture,
            execution_mode=runtime.execution_mode,
            static_match_ids=[item.id for item in static.matches],
            occurrences=occurrences,
            diagnostics=[
                f"runtime_instruction_events:{len(runtime.instructions)}",
                f"runtime_occurrences:{len(occurrences)}",
                f"static_matches:{len(static.matches)}",
            ],
        )
