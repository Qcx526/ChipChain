"""Ground-Truth-free binding of model-authored claims to candidate context."""

from __future__ import annotations

from pydantic import ValidationError

from chipchain.evaluation.candidate import FinalizedCandidateRecord
from chipchain.evaluation.claim_binding_models import ModelClaimBindingAssessment
from chipchain.evaluation.enums import (
    ModelClaimBindingReason,
    ModelClaimBindingStatus,
)
from chipchain.evaluation.errors import (
    InvalidModelClaimBindingInputError,
    ModelClaimBindingError,
)
from chipchain.models.cross_layer import (
    CrossLayerInteraction,
    CrossLayerInteractionType,
)
from chipchain.reasoning.chain_claim import ModelAuthoredChainClaim


_REQUIRED_FIELDS = {
    CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE: (
        "initiating_vulnerability_ids",
        "target_vulnerability_ids",
        "trigger_behavior_ids",
    ),
    CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE: (
        "target_vulnerability_ids",
        "trigger_behavior_ids",
    ),
    CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE: (
        "initiating_vulnerability_ids",
        "affected_execution_ids",
    ),
}
_REQUIRED_MISMATCH_REASONS = {
    "initiating_vulnerability_ids": (
        ModelClaimBindingReason.CLAIM_INITIATING_VULNERABILITY_MISMATCH
    ),
    "target_vulnerability_ids": (
        ModelClaimBindingReason.CLAIM_TARGET_VULNERABILITY_MISMATCH
    ),
    "trigger_behavior_ids": (
        ModelClaimBindingReason.CLAIM_TRIGGER_BEHAVIOR_MISMATCH
    ),
    "affected_execution_ids": (
        ModelClaimBindingReason.CLAIM_AFFECTED_EXECUTION_MISMATCH
    ),
}
_ALL_REFERENCE_FIELDS = (
    "initiating_vulnerability_ids",
    "target_vulnerability_ids",
    "trigger_behavior_ids",
    "propagation_behavior_ids",
    "affected_execution_ids",
    "fault_state_ids",
    "hardware_resource_ids",
    "security_mechanism_ids",
)


class ModelClaimBinder:
    """Compare one explicit model proposal with candidate-side typed context."""

    def assess(
        self,
        candidate: FinalizedCandidateRecord,
        candidate_interaction: CrossLayerInteraction | None = None,
    ) -> ModelClaimBindingAssessment:
        """Return alignment only; never consult Ground Truth or feasibility."""

        detached_candidate = self._snapshot_candidate(candidate)
        interaction = self._optional_interaction(candidate_interaction)
        self._validate_optional_interaction(detached_candidate, interaction)
        claim = detached_candidate.model_authored_chain_claim

        if claim is None:
            return self._result(
                detached_candidate,
                claim=None,
                status=ModelClaimBindingStatus.MISSING,
                reasons=[
                    ModelClaimBindingReason.MODEL_AUTHORED_CLAIM_MISSING
                ],
            )
        if detached_candidate.cross_layer_interaction_id is None:
            return self._result(
                detached_candidate,
                claim=claim,
                status=ModelClaimBindingStatus.UNBOUND,
                reasons=[
                    ModelClaimBindingReason.CANDIDATE_TYPED_INTERACTION_MISSING
                ],
            )
        if interaction is None:
            raise InvalidModelClaimBindingInputError(
                "typed candidate with model claim requires interaction snapshot"
            )
        if claim.interaction_type is not interaction.interaction_type:
            return self._result(
                detached_candidate,
                claim=claim,
                status=ModelClaimBindingStatus.MISMATCHED,
                reasons=[
                    ModelClaimBindingReason.CLAIM_INTERACTION_TYPE_MISMATCH
                ],
            )
        if (
            claim.interaction_type
            is CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
            and claim.initiating_vulnerability_ids
        ):
            return self._result(
                detached_candidate,
                claim=claim,
                status=ModelClaimBindingStatus.MISMATCHED,
                reasons=[ModelClaimBindingReason.CLAIM_TYPE_SHAPE_CONFLICT],
            )
        required_fields = _REQUIRED_FIELDS[claim.interaction_type]
        if any(not getattr(claim, field) for field in required_fields):
            return self._result(
                detached_candidate,
                claim=claim,
                status=ModelClaimBindingStatus.INCOMPLETE,
                reasons=[
                    ModelClaimBindingReason.CLAIM_REQUIRED_FIELDS_MISSING
                ],
            )
        reasons = self._comparison_reasons(
            claim,
            interaction,
            required_fields=required_fields,
        )
        if reasons:
            return self._result(
                detached_candidate,
                claim=claim,
                status=ModelClaimBindingStatus.MISMATCHED,
                reasons=reasons,
            )
        return self._result(
            detached_candidate,
            claim=claim,
            status=ModelClaimBindingStatus.ALIGNED,
            reasons=[ModelClaimBindingReason.CLAIM_ALIGNED],
        )

    @staticmethod
    def _snapshot_candidate(
        value: object,
    ) -> FinalizedCandidateRecord:
        if not isinstance(value, FinalizedCandidateRecord):
            raise InvalidModelClaimBindingInputError(
                "model claim binding requires FinalizedCandidateRecord"
            )
        try:
            return FinalizedCandidateRecord.model_validate(
                value.model_dump(mode="json")
            )
        except (ValidationError, TypeError, ValueError) as exc:
            raise InvalidModelClaimBindingInputError(
                "finalized candidate failed detached revalidation"
            ) from exc

    @staticmethod
    def _optional_interaction(
        value: object,
    ) -> CrossLayerInteraction | None:
        if value is None:
            return None
        if not isinstance(value, CrossLayerInteraction):
            raise InvalidModelClaimBindingInputError(
                "candidate interaction must be CrossLayerInteraction"
            )
        try:
            return CrossLayerInteraction.model_validate(
                value.model_dump(mode="json")
            )
        except (ValidationError, TypeError, ValueError) as exc:
            raise InvalidModelClaimBindingInputError(
                "candidate interaction failed detached revalidation"
            ) from exc

    @staticmethod
    def _validate_optional_interaction(
        candidate: FinalizedCandidateRecord,
        interaction: CrossLayerInteraction | None,
    ) -> None:
        if candidate.cross_layer_interaction_id is None:
            if interaction is not None:
                raise ModelClaimBindingError(
                    "untyped candidate cannot bind an interaction snapshot"
                )
            return
        if interaction is None:
            return
        if interaction.architecture is not candidate.architecture:
            raise ModelClaimBindingError(
                "candidate and interaction architecture mismatch"
            )
        if interaction.id != candidate.cross_layer_interaction_id:
            raise ModelClaimBindingError(
                "candidate interaction identity mismatch"
            )
        if interaction.interaction_type is not candidate.interaction_type:
            raise ModelClaimBindingError("candidate interaction type mismatch")
        if interaction.direction is not candidate.direction:
            raise ModelClaimBindingError(
                "candidate interaction direction mismatch"
            )

    @staticmethod
    def _comparison_reasons(
        claim: ModelAuthoredChainClaim,
        interaction: CrossLayerInteraction,
        *,
        required_fields: tuple[str, ...],
    ) -> list[ModelClaimBindingReason]:
        reasons: set[ModelClaimBindingReason] = set()
        for field in required_fields:
            if getattr(claim, field) != getattr(interaction, field):
                reasons.add(_REQUIRED_MISMATCH_REASONS[field])
        optional_fields = set(_ALL_REFERENCE_FIELDS).difference(required_fields)
        optional_fields.discard("initiating_vulnerability_ids")
        if any(
            getattr(claim, field)
            and not set(getattr(claim, field)).issubset(
                getattr(interaction, field)
            )
            for field in optional_fields
        ):
            reasons.add(
                ModelClaimBindingReason.CLAIM_OPTIONAL_REFERENCE_MISMATCH
            )
        return sorted(reasons, key=lambda item: item.value)

    @staticmethod
    def _result(
        candidate: FinalizedCandidateRecord,
        *,
        claim: ModelAuthoredChainClaim | None,
        status: ModelClaimBindingStatus,
        reasons: list[ModelClaimBindingReason],
    ) -> ModelClaimBindingAssessment:
        return ModelClaimBindingAssessment.from_derived_binding(
            candidate_id=candidate.id,
            benchmark_case_id=candidate.benchmark_case_id,
            architecture=candidate.architecture,
            model_authored_chain_claim_id=(claim.id if claim is not None else None),
            candidate_interaction_id=candidate.cross_layer_interaction_id,
            claimed_interaction_type=(
                claim.interaction_type if claim is not None else None
            ),
            candidate_interaction_type=candidate.interaction_type,
            status=status,
            reason_codes=reasons,
            metadata={
                "binding_semantics": (
                    "model_proposal_to_candidate_context_not_ground_truth"
                ),
                "domain_truth_creation": False,
            },
        )
