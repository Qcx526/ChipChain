"""Objective Phase 9B2A verification of explicit dynamic trigger observations."""

from __future__ import annotations

from pydantic import ValidationError

from chipchain.models import CrossLayerInteraction, Evidence
from chipchain.runtime.errors import RuntimeCapabilityError
from chipchain.runtime.evidence import RuntimeEvidenceNormalizer
from chipchain.runtime.models import RuntimeObservation, RuntimeTrace
from chipchain.runtime.trace import revalidate_runtime_trace
from chipchain.verification.dynamic_bindings import (
    validate_dynamic_trigger_bindings,
)
from chipchain.verification.dynamic_models import (
    DynamicTriggerFact,
    DynamicTriggerObservationBinding,
)
from chipchain.verification.enums import (
    VerificationStatus,
    VerificationSubjectKind,
)
from chipchain.verification.errors import VerificationInputError
from chipchain.verification.models import VerificationRecord


class DynamicTriggerObservationVerifier:
    """Verify that one validated runtime observation matches one trigger fact."""

    verifier_name = "phase9b2a_dynamic_trigger_observation_v1"
    rule_id = "dynamic:trigger-observation:exact-v1"

    def __init__(
        self,
        normalizer: RuntimeEvidenceNormalizer | None = None,
    ) -> None:
        self._normalizer = normalizer or RuntimeEvidenceNormalizer()

    def verify(
        self,
        interaction: CrossLayerInteraction,
        fact: DynamicTriggerFact,
        binding: DynamicTriggerObservationBinding,
        trace: RuntimeTrace,
        evidence: Evidence,
    ) -> VerificationRecord:
        """Return only an observation-level decision, never an interaction verdict."""

        validated_interaction = _snapshot_interaction(interaction)
        validated_fact = _snapshot_fact(fact)
        validated_binding = _snapshot_binding(binding)
        validate_dynamic_trigger_bindings(
            validated_interaction,
            [validated_fact],
            [validated_binding],
        )
        validated_trace = _snapshot_trace(trace)
        validated_evidence = _snapshot_evidence(evidence)

        if validated_binding.runtime_trace_id != validated_trace.manifest.id:
            raise VerificationInputError(
                "dynamic binding runtime_trace_id does not match trace"
            )
        if validated_binding.dynamic_evidence_id != validated_evidence.id:
            raise VerificationInputError(
                "dynamic binding dynamic_evidence_id does not match Evidence"
            )
        if (
            validated_binding.run_id is not None
            and validated_binding.run_id != validated_trace.manifest.run_id
        ):
            raise VerificationInputError(
                "dynamic binding run_id does not match trace manifest"
            )

        observation = next(
            (
                item
                for item in validated_trace.observations
                if item.id == validated_binding.runtime_observation_id
            ),
            None,
        )
        if observation is None:
            return self._record(
                validated_interaction,
                validated_fact,
                validated_binding,
                VerificationStatus.UNKNOWN,
                [],
                ["bound runtime observation could not be resolved from trace snapshot"],
            )

        try:
            regenerated_evidence = self._normalizer.normalize(
                observation,
                validated_trace,
            )
        except (ValidationError, RuntimeCapabilityError, ValueError) as exc:
            raise VerificationInputError(
                "dynamic Evidence regeneration from trace snapshot failed"
            ) from exc
        if regenerated_evidence != validated_evidence:
            raise VerificationInputError(
                "input Dynamic Evidence does not exactly match regenerated Evidence"
            )

        conflicts = _trigger_fact_conflicts(
            validated_interaction,
            validated_fact,
            validated_trace,
            observation,
        )
        if conflicts:
            return self._record(
                validated_interaction,
                validated_fact,
                validated_binding,
                VerificationStatus.REJECTED,
                [validated_evidence.id],
                conflicts,
            )
        return self._record(
            validated_interaction,
            validated_fact,
            validated_binding,
            VerificationStatus.VERIFIED,
            [validated_evidence.id],
            ["runtime observation matches explicit trigger fact"],
            supporting_evidence_ids=[validated_evidence.id],
        )

    def _record(
        self,
        interaction: CrossLayerInteraction,
        fact: DynamicTriggerFact,
        binding: DynamicTriggerObservationBinding,
        status: VerificationStatus,
        evidence_ids: list[str],
        messages: list[str],
        *,
        supporting_evidence_ids: list[str] | None = None,
    ) -> VerificationRecord:
        return VerificationRecord.create(
            interaction_id=interaction.id,
            architecture=interaction.architecture,
            subject_kind=(
                VerificationSubjectKind.DYNAMIC_TRIGGER_OBSERVATION
            ),
            subject_id=binding.id,
            status=status,
            verifier=self.verifier_name,
            evidence_ids=evidence_ids,
            supporting_evidence_ids=supporting_evidence_ids or [],
            rule_ids=[self.rule_id],
            messages=messages,
            metadata={
                "dynamic_trigger_fact_id": fact.id,
                "interaction_reference_id": fact.interaction_reference_id,
                "reference_role": fact.reference_role.value,
                "runtime_observation_id": binding.runtime_observation_id,
                "runtime_trace_id": binding.runtime_trace_id,
                "meaning": {
                    VerificationStatus.VERIFIED: (
                        "runtime_observation_matches_explicit_trigger_fact"
                    ),
                    VerificationStatus.REJECTED: (
                        "runtime_observation_conflicts_with_explicit_trigger_fact"
                    ),
                    VerificationStatus.UNKNOWN: (
                        "runtime_observation_binding_unresolved"
                    ),
                }[status],
            },
        )


def _trigger_fact_conflicts(
    interaction: CrossLayerInteraction,
    fact: DynamicTriggerFact,
    trace: RuntimeTrace,
    observation: RuntimeObservation,
) -> list[str]:
    conflicts: list[str] = []
    if observation.architecture is not interaction.architecture:
        conflicts.append("runtime observation architecture conflicts with interaction")
    if observation.architecture is not fact.architecture:
        conflicts.append("runtime observation architecture conflicts with trigger fact")
    if observation.event_kind is not fact.event_kind:
        conflicts.append("runtime observation event_kind conflicts with trigger fact")
    if observation.pc != fact.program_address:
        conflicts.append("runtime observation PC conflicts with trigger fact")
    if observation.physical_address != fact.physical_address:
        conflicts.append(
            "runtime observation physical_address conflicts with trigger fact"
        )
    if observation.access_size != fact.access_size:
        conflicts.append("runtime observation access_size conflicts with trigger fact")
    if (
        fact.memory_map_id is not None
        and trace.manifest.memory_map_id != fact.memory_map_id
    ):
        conflicts.append("runtime trace memory_map_id conflicts with trigger fact")
    if (
        fact.address_space_id is not None
        and observation.address_space_id != fact.address_space_id
    ):
        conflicts.append(
            "runtime observation address_space_id conflicts with trigger fact"
        )
    return conflicts


def _snapshot_interaction(
    interaction: CrossLayerInteraction,
) -> CrossLayerInteraction:
    try:
        return CrossLayerInteraction.model_validate(
            interaction.model_dump(mode="json")
        )
    except ValidationError as exc:
        raise VerificationInputError(
            "dynamic verifier interaction revalidation failed"
        ) from exc


def _snapshot_fact(fact: DynamicTriggerFact) -> DynamicTriggerFact:
    try:
        return DynamicTriggerFact.model_validate(fact.model_dump(mode="json"))
    except ValidationError as exc:
        raise VerificationInputError(
            "dynamic verifier trigger fact revalidation failed"
        ) from exc


def _snapshot_binding(
    binding: DynamicTriggerObservationBinding,
) -> DynamicTriggerObservationBinding:
    try:
        return DynamicTriggerObservationBinding.model_validate(
            binding.model_dump(mode="json")
        )
    except ValidationError as exc:
        raise VerificationInputError(
            "dynamic verifier binding revalidation failed"
        ) from exc


def _snapshot_trace(trace: RuntimeTrace) -> RuntimeTrace:
    try:
        return revalidate_runtime_trace(trace)
    except (ValidationError, RuntimeCapabilityError) as exc:
        raise VerificationInputError(
            "dynamic verifier RuntimeTrace revalidation failed"
        ) from exc


def _snapshot_evidence(evidence: Evidence) -> Evidence:
    try:
        return Evidence.model_validate(evidence.model_dump(mode="json"))
    except ValidationError as exc:
        raise VerificationInputError(
            "dynamic verifier Evidence revalidation failed"
        ) from exc
