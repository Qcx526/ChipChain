"""Strict Phase 9C Step 4 triggerability aggregation."""

from __future__ import annotations

import hashlib
import json

from pydantic import Field, ValidationError, field_validator, model_validator

from chipchain.hardware_trigger.enums import ArmExecutionMode, TriggerabilityStatus
from chipchain.hardware_trigger.errors import (
    InvalidTriggerabilityInputError,
    TriggerabilityBindingError,
)
from chipchain.hardware_trigger.models import HardwareTriggerSignature
from chipchain.hardware_trigger.runtime_models import (
    RuntimeFirmwareTriggerMatchResult,
    runtime_trigger_match_result_sha256,
    static_trigger_result_sha256,
)
from chipchain.hardware_trigger.static_models import (
    StaticFirmwareTriggerMatch,
    StaticFirmwareTriggerMatchResult,
    _canonical_sha256,
)
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.models.enums import Architecture


def _canonical_payload_hash(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _derived_status(
    *,
    static_match_ids: list[str],
    runtime_occurrence_ids: list[str],
    declared_preconditions_present: bool,
) -> TriggerabilityStatus:
    if not static_match_ids:
        return TriggerabilityStatus.NO_STATIC_TRIGGER_MATCH
    if not runtime_occurrence_ids:
        return TriggerabilityStatus.NOT_OBSERVED_IN_RUNTIME
    if declared_preconditions_present:
        return TriggerabilityStatus.INSUFFICIENT_PRECONDITION_EVIDENCE
    return TriggerabilityStatus.TRIGGERABLE


def triggerability_aggregation_id(
    *,
    status: TriggerabilityStatus,
    signature_id: str,
    hardware_vulnerability_id: str,
    architecture: Architecture,
    execution_mode: ArmExecutionMode,
    artifact_id: str,
    artifact_sha256: str,
    trace_id: str,
    raw_trace_sha256: str,
    static_result_sha256: str,
    runtime_result_sha256: str,
    static_match_ids: list[str],
    runtime_occurrence_ids: list[str],
    declared_preconditions_present: bool,
) -> str:
    """Build deterministic identity from the complete semantic aggregation."""

    payload = {
        "architecture": Architecture(architecture).value,
        "artifact_id": artifact_id,
        "artifact_sha256": _canonical_sha256(artifact_sha256),
        "declared_preconditions_present": declared_preconditions_present,
        "execution_mode": ArmExecutionMode(execution_mode).value,
        "hardware_vulnerability_id": hardware_vulnerability_id,
        "raw_trace_sha256": _canonical_sha256(raw_trace_sha256),
        "runtime_occurrence_ids": sorted(runtime_occurrence_ids),
        "runtime_result_sha256": _canonical_sha256(runtime_result_sha256),
        "signature_id": signature_id,
        "static_match_ids": sorted(static_match_ids),
        "static_result_sha256": _canonical_sha256(static_result_sha256),
        "status": TriggerabilityStatus(status).value,
        "trace_id": trace_id,
    }
    return f"triggerability-aggregation:{_canonical_payload_hash(payload)}"


class TriggerabilityAggregationResult(DomainModel):
    """Firmware triggerability under one declared hardware-trigger contract.

    This is not Evidence, a VerificationRecord, an AttackChain, a vulnerability
    verdict, or proof that QEMU reproduced the hardware-side failure.
    """

    id: Identifier
    status: TriggerabilityStatus
    signature_id: Identifier
    hardware_vulnerability_id: Identifier
    architecture: Architecture
    execution_mode: ArmExecutionMode
    artifact_id: Identifier
    artifact_sha256: Identifier
    trace_id: Identifier
    raw_trace_sha256: Identifier
    static_result_sha256: Identifier
    runtime_result_sha256: Identifier
    static_match_ids: list[Identifier] = Field(default_factory=list)
    runtime_occurrence_ids: list[Identifier] = Field(default_factory=list)
    declared_preconditions_present: bool
    metadata: Metadata = Field(default_factory=dict)

    @field_validator(
        "artifact_sha256",
        "raw_trace_sha256",
        "static_result_sha256",
        "runtime_result_sha256",
        mode="before",
    )
    @classmethod
    def normalize_sha256(cls, value: object) -> str:
        return _canonical_sha256(value)

    @field_validator("static_match_ids", "runtime_occurrence_ids")
    @classmethod
    def normalize_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("triggerability aggregation IDs must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_status_shape_and_identity(self) -> "TriggerabilityAggregationResult":
        if self.architecture is not Architecture.ARM:
            raise ValueError("triggerability aggregation supports ARM only")
        if self.execution_mode is not ArmExecutionMode.A32:
            raise ValueError("triggerability aggregation supports ARM A32 only")
        if not self.static_match_ids and self.runtime_occurrence_ids:
            raise ValueError("runtime occurrences require static trigger matches")
        expected_status = _derived_status(
            static_match_ids=self.static_match_ids,
            runtime_occurrence_ids=self.runtime_occurrence_ids,
            declared_preconditions_present=self.declared_preconditions_present,
        )
        if self.status is not expected_status:
            raise ValueError("triggerability status is not derived from result shape")
        expected_id = triggerability_aggregation_id(
            status=self.status,
            signature_id=self.signature_id,
            hardware_vulnerability_id=self.hardware_vulnerability_id,
            architecture=self.architecture,
            execution_mode=self.execution_mode,
            artifact_id=self.artifact_id,
            artifact_sha256=self.artifact_sha256,
            trace_id=self.trace_id,
            raw_trace_sha256=self.raw_trace_sha256,
            static_result_sha256=self.static_result_sha256,
            runtime_result_sha256=self.runtime_result_sha256,
            static_match_ids=self.static_match_ids,
            runtime_occurrence_ids=self.runtime_occurrence_ids,
            declared_preconditions_present=self.declared_preconditions_present,
        )
        if self.id != expected_id:
            raise ValueError("TriggerabilityAggregationResult ID is not deterministic")
        return self

    @classmethod
    def create(cls, **values: object) -> "TriggerabilityAggregationResult":
        """Derive status and identity; callers cannot select either arbitrarily."""

        data = dict(values)
        static_ids = sorted(str(item) for item in data.get("static_match_ids", []))
        runtime_ids = sorted(
            str(item) for item in data.get("runtime_occurrence_ids", [])
        )
        declared = bool(data["declared_preconditions_present"])
        status = _derived_status(
            static_match_ids=static_ids,
            runtime_occurrence_ids=runtime_ids,
            declared_preconditions_present=declared,
        )
        identity = triggerability_aggregation_id(
            status=status,
            signature_id=str(data["signature_id"]),
            hardware_vulnerability_id=str(data["hardware_vulnerability_id"]),
            architecture=Architecture(data["architecture"]),
            execution_mode=ArmExecutionMode(data["execution_mode"]),
            artifact_id=str(data["artifact_id"]),
            artifact_sha256=str(data["artifact_sha256"]),
            trace_id=str(data["trace_id"]),
            raw_trace_sha256=str(data["raw_trace_sha256"]),
            static_result_sha256=str(data["static_result_sha256"]),
            runtime_result_sha256=str(data["runtime_result_sha256"]),
            static_match_ids=static_ids,
            runtime_occurrence_ids=runtime_ids,
            declared_preconditions_present=declared,
        )
        data["static_match_ids"] = static_ids
        data["runtime_occurrence_ids"] = runtime_ids
        data["status"] = status
        return cls(id=identity, **data)


class TriggerabilityAggregator:
    """Compose prior hardware contract and exact static/runtime firmware facts."""

    def aggregate(
        self,
        signature: HardwareTriggerSignature,
        static_result: StaticFirmwareTriggerMatchResult,
        runtime_result: RuntimeFirmwareTriggerMatchResult,
    ) -> TriggerabilityAggregationResult:
        """Detached-revalidate all inputs, cross-bind them, and derive status."""

        if not isinstance(signature, HardwareTriggerSignature):
            raise InvalidTriggerabilityInputError(
                "triggerability aggregation requires HardwareTriggerSignature"
            )
        if not isinstance(static_result, StaticFirmwareTriggerMatchResult):
            raise InvalidTriggerabilityInputError(
                "triggerability aggregation requires StaticFirmwareTriggerMatchResult"
            )
        if not isinstance(runtime_result, RuntimeFirmwareTriggerMatchResult):
            raise InvalidTriggerabilityInputError(
                "triggerability aggregation requires RuntimeFirmwareTriggerMatchResult"
            )
        try:
            detached_signature = HardwareTriggerSignature.model_validate(
                signature.model_dump(mode="json")
            )
            detached_static = StaticFirmwareTriggerMatchResult.model_validate(
                static_result.model_dump(mode="json")
            )
            detached_runtime = RuntimeFirmwareTriggerMatchResult.model_validate(
                runtime_result.model_dump(mode="json")
            )
        except (ValidationError, TypeError, ValueError) as exc:
            raise InvalidTriggerabilityInputError(
                "triggerability inputs failed detached revalidation"
            ) from exc

        self._validate_signature_static(detached_signature, detached_static)
        self._validate_static_runtime(detached_static, detached_runtime)
        self._validate_runtime_occurrences(detached_static, detached_runtime)
        declared_preconditions = bool(
            detached_signature.preconditions.privilege_mode is not None
            or detached_signature.preconditions.register_preconditions
            or detached_signature.preconditions.memory_preconditions
        )
        static_hash = static_trigger_result_sha256(detached_static)
        runtime_hash = runtime_trigger_match_result_sha256(detached_runtime)
        return TriggerabilityAggregationResult.create(
            signature_id=detached_signature.id,
            hardware_vulnerability_id=(
                detached_signature.hardware_vulnerability_id
            ),
            architecture=detached_signature.architecture,
            execution_mode=detached_signature.execution_mode,
            artifact_id=detached_static.artifact_id,
            artifact_sha256=detached_static.artifact_sha256,
            trace_id=detached_runtime.trace_id,
            raw_trace_sha256=detached_runtime.raw_trace_sha256,
            static_result_sha256=static_hash,
            runtime_result_sha256=runtime_hash,
            static_match_ids=[item.id for item in detached_static.matches],
            runtime_occurrence_ids=[
                item.id for item in detached_runtime.occurrences
            ],
            declared_preconditions_present=declared_preconditions,
            metadata={
                "aggregation_scope": (
                    "firmware_triggerability_under_declared_hardware_contract"
                )
            },
        )

    @staticmethod
    def _validate_signature_static(
        signature: HardwareTriggerSignature,
        static: StaticFirmwareTriggerMatchResult,
    ) -> None:
        if (
            signature.architecture,
            signature.execution_mode,
            signature.id,
            signature.hardware_vulnerability_id,
        ) != (
            static.architecture,
            static.execution_mode,
            static.signature_id,
            static.hardware_vulnerability_id,
        ):
            raise TriggerabilityBindingError(
                "hardware signature and static trigger result binding mismatch"
            )
        for match in static.matches:
            words = [item.instruction_word for item in match.instruction_locations]
            if words != signature.instruction_sequence:
                raise TriggerabilityBindingError(
                    "static trigger words do not equal hardware signature sequence"
                )

    @staticmethod
    def _validate_static_runtime(
        static: StaticFirmwareTriggerMatchResult,
        runtime: RuntimeFirmwareTriggerMatchResult,
    ) -> None:
        if (
            static.architecture,
            static.execution_mode,
            static.artifact_id,
            static.artifact_sha256,
            static.signature_id,
            static.hardware_vulnerability_id,
        ) != (
            runtime.architecture,
            runtime.execution_mode,
            runtime.artifact_id,
            runtime.artifact_sha256,
            runtime.signature_id,
            runtime.hardware_vulnerability_id,
        ):
            raise TriggerabilityBindingError(
                "static and runtime trigger result binding mismatch"
            )
        expected_static_hash = static_trigger_result_sha256(static)
        if runtime.static_result_sha256 != expected_static_hash:
            raise TriggerabilityBindingError(
                "runtime result static semantic hash mismatch"
            )
        expected_static_ids = sorted(item.id for item in static.matches)
        if runtime.static_match_ids != expected_static_ids:
            raise TriggerabilityBindingError(
                "runtime result static match IDs are not the exact static set"
            )

    @staticmethod
    def _validate_runtime_occurrences(
        static: StaticFirmwareTriggerMatchResult,
        runtime: RuntimeFirmwareTriggerMatchResult,
    ) -> None:
        match_by_id: dict[str, StaticFirmwareTriggerMatch] = {
            item.id: item for item in static.matches
        }
        for occurrence in runtime.occurrences:
            referenced = match_by_id.get(occurrence.static_match_id)
            if referenced is None:
                raise TriggerabilityBindingError(
                    "runtime occurrence references an unknown static match"
                )
            expected = [
                (item.instruction_address, item.instruction_word)
                for item in referenced.instruction_locations
            ]
            actual = [
                (item.pc, item.instruction_word)
                for item in occurrence.instructions
            ]
            if actual != expected:
                raise TriggerabilityBindingError(
                    "runtime occurrence does not equal referenced static PC/word sequence"
                )
