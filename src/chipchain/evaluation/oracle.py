"""Ground-Truth-free candidate-side objective chain feasibility oracle."""

from __future__ import annotations

from pydantic import ValidationError

from chipchain.evaluation.candidate import FinalizedCandidateRecord
from chipchain.evaluation.errors import (
    ChainFeasibilityBindingError,
    InvalidChainFeasibilityInputError,
)
from chipchain.evaluation.feasibility_models import (
    ChainFeasibilityAssessment,
    ObjectiveEvaluationFailure,
)
from chipchain.evaluation.models import BenchmarkArtifactReference
from chipchain.hardware_trigger.aggregation import TriggerabilityAggregationResult
from chipchain.models.cross_layer import (
    CrossLayerInteraction,
    CrossLayerInteractionType,
)


class ChainFeasibilityOracle:
    """Assess one finalized candidate using objective candidate-side facts only."""

    def assess(
        self,
        candidate: FinalizedCandidateRecord,
        artifact: BenchmarkArtifactReference,
        *,
        candidate_interaction: CrossLayerInteraction | None = None,
        triggerability: TriggerabilityAggregationResult | None = None,
        infrastructure_failure: ObjectiveEvaluationFailure | None = None,
    ) -> ChainFeasibilityAssessment:
        """Derive one outcome without accepting or consulting Ground Truth."""

        detached_candidate = self._snapshot(
            candidate,
            FinalizedCandidateRecord,
            "FinalizedCandidateRecord",
        )
        detached_artifact = self._snapshot(
            artifact,
            BenchmarkArtifactReference,
            "BenchmarkArtifactReference",
        )
        interaction = self._optional_snapshot(
            candidate_interaction,
            CrossLayerInteraction,
            "CrossLayerInteraction",
        )
        trigger = self._optional_snapshot(
            triggerability,
            TriggerabilityAggregationResult,
            "TriggerabilityAggregationResult",
        )
        failure = self._optional_snapshot(
            infrastructure_failure,
            ObjectiveEvaluationFailure,
            "ObjectiveEvaluationFailure",
        )

        if detached_candidate.architecture is not detached_artifact.architecture:
            raise ChainFeasibilityBindingError(
                "candidate and evaluation artifact architecture mismatch"
            )
        if detached_candidate.cross_layer_interaction_id is None:
            if interaction is not None or trigger is not None or failure is not None:
                raise ChainFeasibilityBindingError(
                    "untyped candidate cannot consume objective interaction facts"
                )
            return self._assessment(
                detached_candidate,
                detached_artifact,
                interaction=None,
                triggerability=None,
                failure=None,
            )
        if interaction is None:
            raise InvalidChainFeasibilityInputError(
                "typed candidate requires its candidate-side interaction snapshot"
            )
        self._validate_candidate_interaction(detached_candidate, interaction)

        if (
            interaction.interaction_type
            is CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
        ):
            if trigger is not None:
                raise ChainFeasibilityBindingError(
                    "Type III cannot consume software-to-hardware triggerability"
                )
            if failure is not None:
                raise ChainFeasibilityBindingError(
                    "Type III capability gap cannot be replaced by infrastructure failure"
                )
            return self._assessment(
                detached_candidate,
                detached_artifact,
                interaction=interaction,
                triggerability=None,
                failure=None,
            )

        if trigger is not None:
            self._validate_triggerability(
                detached_candidate,
                detached_artifact,
                interaction,
                trigger,
            )
        if failure is not None:
            self._validate_failure(detached_candidate, failure)
            if trigger is not None:
                raise ChainFeasibilityBindingError(
                    "completed triggerability and infrastructure failure conflict"
                )
        return self._assessment(
            detached_candidate,
            detached_artifact,
            interaction=interaction,
            triggerability=trigger,
            failure=failure,
        )

    @staticmethod
    def _snapshot(value: object, model_type: type, label: str):
        if not isinstance(value, model_type):
            raise InvalidChainFeasibilityInputError(
                f"chain feasibility requires {label}"
            )
        try:
            return model_type.model_validate(value.model_dump(mode="json"))
        except (ValidationError, TypeError, ValueError) as exc:
            raise InvalidChainFeasibilityInputError(
                f"{label} failed detached revalidation"
            ) from exc

    @classmethod
    def _optional_snapshot(cls, value: object | None, model_type: type, label: str):
        if value is None:
            return None
        return cls._snapshot(value, model_type, label)

    @staticmethod
    def _validate_candidate_interaction(
        candidate: FinalizedCandidateRecord,
        interaction: CrossLayerInteraction,
    ) -> None:
        if (
            candidate.cross_layer_interaction_id,
            candidate.interaction_type,
            candidate.direction,
            candidate.architecture,
        ) != (
            interaction.id,
            interaction.interaction_type,
            interaction.direction,
            interaction.architecture,
        ):
            raise ChainFeasibilityBindingError(
                "candidate-side interaction binding mismatch"
            )

    @staticmethod
    def _validate_triggerability(
        candidate: FinalizedCandidateRecord,
        artifact: BenchmarkArtifactReference,
        interaction: CrossLayerInteraction,
        triggerability: TriggerabilityAggregationResult,
    ) -> None:
        if triggerability.architecture is not candidate.architecture:
            raise ChainFeasibilityBindingError(
                "triggerability and candidate architecture mismatch"
            )
        if (
            triggerability.artifact_id,
            triggerability.artifact_sha256,
        ) != (artifact.artifact_id, artifact.artifact_sha256):
            raise ChainFeasibilityBindingError(
                "triggerability and evaluation artifact binding mismatch"
            )
        if (
            triggerability.hardware_vulnerability_id
            not in interaction.target_vulnerability_ids
        ):
            raise ChainFeasibilityBindingError(
                "triggerability hardware vulnerability is not an interaction target"
            )

    @staticmethod
    def _validate_failure(
        candidate: FinalizedCandidateRecord,
        failure: ObjectiveEvaluationFailure,
    ) -> None:
        if (
            failure.candidate_id,
            failure.benchmark_case_id,
            failure.architecture,
        ) != (
            candidate.id,
            candidate.benchmark_case_id,
            candidate.architecture,
        ):
            raise ChainFeasibilityBindingError(
                "objective infrastructure failure binding mismatch"
            )

    @staticmethod
    def _assessment(
        candidate: FinalizedCandidateRecord,
        artifact: BenchmarkArtifactReference,
        *,
        interaction: CrossLayerInteraction | None,
        triggerability: TriggerabilityAggregationResult | None,
        failure: ObjectiveEvaluationFailure | None,
    ) -> ChainFeasibilityAssessment:
        return ChainFeasibilityAssessment.create(
            candidate_id=candidate.id,
            benchmark_case_id=candidate.benchmark_case_id,
            architecture=candidate.architecture,
            interaction_id=interaction.id if interaction is not None else None,
            interaction_type=(
                interaction.interaction_type if interaction is not None else None
            ),
            artifact_id=artifact.artifact_id,
            artifact_sha256=artifact.artifact_sha256,
            triggerability_aggregation_id=(
                triggerability.id if triggerability is not None else None
            ),
            triggerability_status=(
                triggerability.status if triggerability is not None else None
            ),
            infrastructure_failure_id=failure.id if failure is not None else None,
            metadata={
                "assessment_scope": "candidate_side_objective_facts_only",
                "ground_truth_consulted": False,
                "llm_authorship_of_context_binding": False,
            },
        )
