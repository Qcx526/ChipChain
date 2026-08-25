"""Deterministic, non-feasibility results for model claim binding."""

from __future__ import annotations

from pydantic import Field, field_validator, model_validator

from chipchain.evaluation.enums import (
    ModelClaimBindingReason,
    ModelClaimBindingStatus,
)
from chipchain.evaluation.models import _canonical_hash
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.models.cross_layer import CrossLayerInteractionType
from chipchain.models.enums import Architecture


_MISMATCH_REASONS = frozenset(
    {
        ModelClaimBindingReason.CLAIM_TYPE_SHAPE_CONFLICT,
        ModelClaimBindingReason.CLAIM_INTERACTION_TYPE_MISMATCH,
        ModelClaimBindingReason.CLAIM_INITIATING_VULNERABILITY_MISMATCH,
        ModelClaimBindingReason.CLAIM_TARGET_VULNERABILITY_MISMATCH,
        ModelClaimBindingReason.CLAIM_TRIGGER_BEHAVIOR_MISMATCH,
        ModelClaimBindingReason.CLAIM_AFFECTED_EXECUTION_MISMATCH,
        ModelClaimBindingReason.CLAIM_OPTIONAL_REFERENCE_MISMATCH,
    }
)
_FORBIDDEN_METADATA_FRAGMENTS = (
    "attackchain",
    "confidence",
    "feasibility",
    "hitrate",
    "metric",
    "probability",
    "score",
    "verification",
    "verified",
    "verdict",
)


def model_claim_binding_assessment_id(
    *,
    candidate_id: str,
    benchmark_case_id: str,
    architecture: Architecture,
    model_authored_chain_claim_id: str | None,
    candidate_interaction_id: str | None,
    claimed_interaction_type: CrossLayerInteractionType | None,
    candidate_interaction_type: CrossLayerInteractionType | None,
    status: ModelClaimBindingStatus,
    reason_codes: list[ModelClaimBindingReason],
) -> str:
    """Build identity without confidence, provider, prose, or metadata."""

    return _canonical_hash(
        "model-claim-binding-assessment",
        {
            "architecture": Architecture(architecture).value,
            "benchmark_case_id": benchmark_case_id,
            "candidate_id": candidate_id,
            "candidate_interaction_id": candidate_interaction_id,
            "candidate_interaction_type": (
                candidate_interaction_type.value
                if candidate_interaction_type is not None
                else None
            ),
            "claimed_interaction_type": (
                claimed_interaction_type.value
                if claimed_interaction_type is not None
                else None
            ),
            "model_authored_chain_claim_id": model_authored_chain_claim_id,
            "reason_codes": sorted(item.value for item in reason_codes),
            "status": ModelClaimBindingStatus(status).value,
        },
    )


def _validate_binding_metadata(metadata: Metadata) -> Metadata:
    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                normalized = "".join(
                    character
                    for character in str(key).lower()
                    if character.isalnum()
                )
                if any(
                    fragment in normalized
                    for fragment in _FORBIDDEN_METADATA_FRAGMENTS
                ):
                    raise ValueError(
                        "claim binding metadata must not contain verdict or metric fields"
                    )
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(metadata)
    return metadata


class ModelClaimBindingAssessment(DomainModel):
    """One claim/context comparison, never feasibility or verified truth."""

    id: Identifier
    candidate_id: Identifier
    benchmark_case_id: Identifier
    architecture: Architecture
    model_authored_chain_claim_id: Identifier | None = None
    candidate_interaction_id: Identifier | None = None
    claimed_interaction_type: CrossLayerInteractionType | None = None
    candidate_interaction_type: CrossLayerInteractionType | None = None
    status: ModelClaimBindingStatus
    reason_codes: list[ModelClaimBindingReason] = Field(min_length=1)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("reason_codes")
    @classmethod
    def normalize_reasons(
        cls, values: list[ModelClaimBindingReason]
    ) -> list[ModelClaimBindingReason]:
        if len(values) != len(set(values)):
            raise ValueError("model claim binding reason codes must be unique")
        return sorted(values, key=lambda item: item.value)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_binding_metadata(value)

    @model_validator(mode="after")
    def validate_shape_and_identity(self) -> "ModelClaimBindingAssessment":
        if self.architecture is not Architecture.ARM:
            raise ValueError("Phase 10A model claim binding supports ARM only")
        if (self.model_authored_chain_claim_id is None) != (
            self.claimed_interaction_type is None
        ):
            raise ValueError("binding claim identity/type are all-or-none")
        if (self.candidate_interaction_id is None) != (
            self.candidate_interaction_type is None
        ):
            raise ValueError("binding candidate interaction fields are all-or-none")
        expected_reasons: list[ModelClaimBindingReason] | None = None
        if self.status is ModelClaimBindingStatus.MISSING:
            if self.model_authored_chain_claim_id is not None:
                raise ValueError("MISSING binding cannot retain a model claim")
            expected_reasons = [
                ModelClaimBindingReason.MODEL_AUTHORED_CLAIM_MISSING
            ]
        elif self.status is ModelClaimBindingStatus.UNBOUND:
            if (
                self.model_authored_chain_claim_id is None
                or self.candidate_interaction_id is not None
            ):
                raise ValueError("UNBOUND binding has incompatible identities")
            expected_reasons = [
                ModelClaimBindingReason.CANDIDATE_TYPED_INTERACTION_MISSING
            ]
        else:
            if (
                self.model_authored_chain_claim_id is None
                or self.candidate_interaction_id is None
            ):
                raise ValueError("compared binding requires claim and interaction")
            if self.status is ModelClaimBindingStatus.ALIGNED:
                expected_reasons = [ModelClaimBindingReason.CLAIM_ALIGNED]
            elif self.status is ModelClaimBindingStatus.INCOMPLETE:
                expected_reasons = [
                    ModelClaimBindingReason.CLAIM_REQUIRED_FIELDS_MISSING
                ]
            elif not set(self.reason_codes).issubset(_MISMATCH_REASONS):
                raise ValueError(
                    "model claim binding status/reasons are incompatible"
                )
            types_match = (
                self.claimed_interaction_type
                is self.candidate_interaction_type
            )
            type_mismatch_reasons = [
                ModelClaimBindingReason.CLAIM_INTERACTION_TYPE_MISMATCH
            ]
            if not types_match and (
                self.status is not ModelClaimBindingStatus.MISMATCHED
                or self.reason_codes != type_mismatch_reasons
            ):
                raise ValueError(
                    "interaction type mismatch must remain a mismatched outcome"
                )
            if types_match and (
                ModelClaimBindingReason.CLAIM_INTERACTION_TYPE_MISMATCH
                in self.reason_codes
            ):
                raise ValueError(
                    "matching interaction types cannot use type-mismatch reason"
                )
            if (
                ModelClaimBindingReason.CLAIM_TYPE_SHAPE_CONFLICT
                in self.reason_codes
                and self.claimed_interaction_type
                is not CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
            ):
                raise ValueError(
                    "claim type-shape conflict applies only to Type II"
                )
        if expected_reasons is not None and self.reason_codes != expected_reasons:
            raise ValueError("model claim binding status/reasons are incompatible")
        expected_id = model_claim_binding_assessment_id(
            candidate_id=self.candidate_id,
            benchmark_case_id=self.benchmark_case_id,
            architecture=self.architecture,
            model_authored_chain_claim_id=self.model_authored_chain_claim_id,
            candidate_interaction_id=self.candidate_interaction_id,
            claimed_interaction_type=self.claimed_interaction_type,
            candidate_interaction_type=self.candidate_interaction_type,
            status=self.status,
            reason_codes=self.reason_codes,
        )
        if self.id != expected_id:
            raise ValueError("ModelClaimBindingAssessment ID is not deterministic")
        return self

    @classmethod
    def from_derived_binding(
        cls,
        *,
        candidate_id: str,
        benchmark_case_id: str,
        architecture: Architecture,
        model_authored_chain_claim_id: str | None,
        candidate_interaction_id: str | None,
        claimed_interaction_type: CrossLayerInteractionType | None,
        candidate_interaction_type: CrossLayerInteractionType | None,
        status: ModelClaimBindingStatus,
        reason_codes: list[ModelClaimBindingReason],
        metadata: Metadata | None = None,
    ) -> "ModelClaimBindingAssessment":
        """Construct one binder-derived result from closed semantics."""

        identity = model_claim_binding_assessment_id(
            candidate_id=candidate_id,
            benchmark_case_id=benchmark_case_id,
            architecture=architecture,
            model_authored_chain_claim_id=model_authored_chain_claim_id,
            candidate_interaction_id=candidate_interaction_id,
            claimed_interaction_type=claimed_interaction_type,
            candidate_interaction_type=candidate_interaction_type,
            status=status,
            reason_codes=reason_codes,
        )
        return cls(
            id=identity,
            candidate_id=candidate_id,
            benchmark_case_id=benchmark_case_id,
            architecture=architecture,
            model_authored_chain_claim_id=model_authored_chain_claim_id,
            candidate_interaction_id=candidate_interaction_id,
            claimed_interaction_type=claimed_interaction_type,
            candidate_interaction_type=candidate_interaction_type,
            status=status,
            reason_codes=reason_codes,
            metadata=metadata or {},
        )
