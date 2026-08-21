"""Phase 9B2B Step 7 dynamic reasoning-context binding tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from chipchain.agents import AgentWorkflow, CodeAgent, ReasoningContext
from chipchain.knowledge import (
    DeterministicKnowledgeRetriever,
    InMemoryKnowledgeEntryRepository,
    KnowledgeRetrievalQuery,
)
from chipchain.models import (
    Architecture,
    AttackChain,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    Evidence,
    Layer,
)
from chipchain.reasoning import (
    AttackHypothesis,
    EvidenceCategory,
    EvidenceRequest,
    ReasoningResult,
)
from chipchain.runtime import RuntimeEventKind, RuntimeObservation
from chipchain.verification import HardwareAddress, ProgramAddress
from chipchain.verification.models import VerificationRecord


def _interaction() -> CrossLayerInteraction:
    return CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=(
            CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
        ),
        source_layer=Layer.FIRMWARE,
        target_layer=Layer.HARDWARE,
        target_vulnerability_ids=["fixture-hardware-condition"],
        trigger_behavior_ids=["fixture-mmio-trigger"],
        hardware_resource_ids=["fixture-mmio-register"],
        referenced_architectures=[Architecture.ARM],
        metadata={"fixture": True},
    )


def _observation(
    *, architecture: Architecture = Architecture.ARM
) -> RuntimeObservation:
    return RuntimeObservation.create(
        trace_id="fixture-step7-trace",
        architecture=architecture,
        sequence_index=1,
        vcpu_index=0,
        event_kind=RuntimeEventKind.MMIO_WRITE,
        pc=ProgramAddress(value="0x10008"),
        physical_address=HardwareAddress(value="0x40000000"),
        is_io=True,
        access_size=4,
        address_space_id="fixture-system-memory",
        host_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        metadata={"fixture": True, "untrusted_note": "not reasoning truth"},
    )


def _knowledge_result():
    query = KnowledgeRetrievalQuery.create(
        architecture=Architecture.ARM,
        text="fixture arm mmio context",
        metadata={"fixture": True},
    )
    return DeterministicKnowledgeRetriever(
        InMemoryKnowledgeEntryRepository([])
    ).retrieve(query)


def _context(
    *, runtime_observations: list[RuntimeObservation] | None = None
) -> ReasoningContext:
    interaction = _interaction()
    return ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id=interaction.id,
        affected_components=["fixture-arm-driver", "fixture-mmio-register"],
        available_evidence_ids=["fixture-static-evidence"],
        dynamic_trigger_fact_reference="dynamic-trigger-fact:fixture-reference",
        attack_pattern_reference="CAPEC-fixture-reference",
        cross_layer_interaction=interaction,
        runtime_observations=runtime_observations,
        knowledge_retrieval_result=_knowledge_result(),
    )


def test_runtime_observation_can_influence_hypothesis_without_truth_creation() -> None:
    observation = _observation()
    without_runtime = CodeAgent(_context()).produce_hypothesis()
    context = _context(runtime_observations=[observation])
    with_runtime = CodeAgent(context).produce_hypothesis()

    assert with_runtime.id != without_runtime.id
    assert observation.id in with_runtime.description
    assert RuntimeEventKind.MMIO_WRITE.value in with_runtime.description
    assert context.cross_layer_interaction is not None
    assert context.knowledge_retrieval_result is not None
    assert context.runtime_observations[0].metadata == {}
    assert context.runtime_observations[0].host_timestamp is None
    assert context.cross_layer_interaction.metadata == {}
    assert context.knowledge_retrieval_result.metadata == {}
    assert with_runtime.metadata["context_binding_semantics"] == (
        "reasoning_input_only_not_verification"
    )


def test_runtime_observation_cannot_directly_create_verification() -> None:
    observation = _observation()
    session = AgentWorkflow().execute(
        _context(runtime_observations=[observation])
    )
    outputs = [
        *session.hypotheses,
        *session.evidence_requests,
        *session.reasoning_results,
        session.final_reasoning_result,
    ]

    assert all(
        type(item) in {AttackHypothesis, EvidenceRequest, ReasoningResult}
        for item in outputs
    )
    assert not any(
        isinstance(item, (Evidence, VerificationRecord, AttackChain))
        for item in outputs
    )
    assert observation.id not in (
        session.final_reasoning_result.supporting_evidence_ids
    )
    assert session.final_reasoning_result.confidence == 0.0
    serialized = session.model_dump(mode="json")
    assert "verification_record" not in serialized
    assert "verification_status" not in serialized
    assert "vulnerability_verdict" not in serialized


def test_missing_runtime_observation_generates_evidence_request() -> None:
    requests = CodeAgent(_context()).request_evidence()
    runtime_request = next(
        item
        for item in requests
        if item.evidence_type is EvidenceCategory.RUNTIME_OBSERVATION
    )

    assert type(runtime_request) is EvidenceRequest
    assert runtime_request.metadata["context_gap"] == (
        "runtime_observation_context_missing"
    )
    assert runtime_request.dynamic_trigger_fact_reference == (
        "dynamic-trigger-fact:fixture-reference"
    )


def test_dynamic_context_binding_rejects_cross_architecture_observation() -> None:
    with pytest.raises(ValidationError, match="observation architecture mismatch"):
        _context(runtime_observations=[_observation(architecture=Architecture.RISC_V)])
