"""Demonstrate the Phase 9B1 -> Phase 9B2A evidence chain offline.

This owned synthetic demo verifies only that one runtime observation matches an
explicit trigger fact. It does not produce a vulnerability, interaction,
causality, BehaviorEdge, or AttackChain verdict.
"""

from __future__ import annotations

from pathlib import Path

from chipchain.models import (
    Architecture,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    Layer,
)
from chipchain.runtime import (
    RuntimeEventKind,
    RuntimeEvidenceNormalizer,
    load_runtime_trace,
)
from chipchain.verification.aggregation import (
    StaticDynamicFactAggregation,
)
from chipchain.verification.dynamic import DynamicTriggerObservationVerifier
from chipchain.verification.dynamic_models import (
    DynamicTriggerFact,
    DynamicTriggerObservationBinding,
)
from chipchain.verification.enums import (
    VerificationStatus,
    VerificationSubjectKind,
)
from chipchain.verification.models import VerificationRecord


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_TRACE_FIXTURE = (
    ROOT / "tests" / "fixtures" / "runtime" / "arm_mmio_runtime_trace.json"
)
TRIGGER_REFERENCE_ID = "fixture-phase9b2a-mmio-trigger"
STATIC_EVIDENCE_ID = "fixture-phase9b2a-static-trigger-evidence"


def build_demo_results() -> tuple[
    VerificationRecord,
    StaticDynamicFactAggregation,
]:
    """Build deterministic observation-level verification and aggregation."""

    trace = load_runtime_trace(RUNTIME_TRACE_FIXTURE)
    observation = next(
        item
        for item in trace.observations
        if item.event_kind is RuntimeEventKind.MMIO_WRITE
    )
    if (
        observation.pc is None
        or observation.physical_address is None
        or observation.access_size is None
    ):
        raise RuntimeError("owned MMIO fixture is missing required observation fields")

    interaction = CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=(
            CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
        ),
        source_layer=Layer.DRIVER,
        target_layer=Layer.HARDWARE,
        target_vulnerability_ids=[
            "fixture-phase9b2a-hardware-vulnerability-hypothesis"
        ],
        trigger_behavior_ids=[TRIGGER_REFERENCE_ID],
        metadata={
            "fixture": True,
            "not_benchmark": True,
            "not_real_vulnerability": True,
            "owned": True,
            "synthetic": True,
        },
    )
    fact = DynamicTriggerFact.create(
        interaction,
        interaction_reference_id=TRIGGER_REFERENCE_ID,
        event_kind=observation.event_kind,
        program_address=observation.pc,
        physical_address=observation.physical_address,
        access_size=observation.access_size,
        address_space_id=observation.address_space_id,
        memory_map_id=trace.manifest.memory_map_id,
        metadata={"fixture": True, "owned": True, "synthetic": True},
    )
    evidence = RuntimeEvidenceNormalizer().normalize(observation, trace)
    binding = DynamicTriggerObservationBinding.create(
        fact,
        dynamic_evidence_id=evidence.id,
        runtime_trace_id=trace.manifest.id,
        runtime_observation_id=observation.id,
        run_id=trace.manifest.run_id,
        metadata={"fixture": True, "owned": True, "synthetic": True},
    )
    dynamic_record = DynamicTriggerObservationVerifier().verify(
        interaction,
        fact,
        binding,
        trace,
        evidence,
    )

    static_record = VerificationRecord.create(
        interaction_id=interaction.id,
        architecture=interaction.architecture,
        subject_kind=VerificationSubjectKind.INTERACTION_PARTICIPANT,
        subject_id=f"trigger_behavior:{TRIGGER_REFERENCE_ID}",
        status=VerificationStatus.VERIFIED,
        verifier="phase9b2a_owned_static_fixture_v1",
        evidence_ids=[STATIC_EVIDENCE_ID],
        supporting_evidence_ids=[STATIC_EVIDENCE_ID],
        rule_ids=["fixture:static-trigger-observation:v1"],
        messages=["owned static fixture matches the explicit trigger behavior"],
        metadata={"fixture": True, "owned": True, "synthetic": True},
    )
    aggregation = StaticDynamicFactAggregation.create(
        static_record,
        dynamic_record,
    )
    return dynamic_record, aggregation


def main() -> tuple[VerificationRecord, StaticDynamicFactAggregation]:
    """Print the two evidence-chain results without promoting their meaning."""

    dynamic_record, aggregation = build_demo_results()
    print("Dynamic trigger verification:")
    print(dynamic_record.status.name)
    print(dynamic_record.model_dump_json(indent=2))
    print("Aggregation:")
    print(aggregation.status.value)
    print(aggregation.model_dump_json(indent=2))
    print(
        "Boundary: observation matches trigger fact only; no vulnerability, "
        "interaction, causality, BehaviorEdge, or AttackChain verdict."
    )
    return dynamic_record, aggregation


if __name__ == "__main__":
    main()
