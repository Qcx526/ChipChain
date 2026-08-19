"""Run the owned ARM ELF through Phase 9A-R2 Type II verification."""

from __future__ import annotations

import json
from pathlib import Path

from chipchain.analysis import AngrAnalyzer, MemoryMap, ProgramArtifact, ingest_analysis_result
from chipchain.candidate import CrossGraphCandidateSearcher
from chipchain.graph import NetworkXGraphRepository
from chipchain.knowledge import NetworkXKnowledgeGraphRepository, VulnerabilityKnowledgeBuilder
from chipchain.models import Architecture, CrossLayerInteraction, Layer, RelationType, VulnerabilitySample
from chipchain.reasoning import InMemoryEvidenceResolver
from chipchain.verification import (
    InteractionVerificationInput,
    InteractionVerificationPipeline,
    RequiredFactCategory,
)


def build_demo_material():
    """Build the owned repositories and explicit interaction verification input."""
    root = Path(__file__).resolve().parents[1]
    mmio = root / "tests" / "fixtures" / "angr" / "arm_mmio"
    memory_map = MemoryMap.model_validate_json((mmio / "memory_map.json").read_text(encoding="utf-8"))
    artifact = ProgramArtifact(id="synthetic-arm-mmio", architecture=Architecture.ARM,
        artifact_type="elf", program_layer=Layer.DRIVER, path=str(mmio / "arm_mmio.elf"),
        fixture_identifier="synthetic-arm-mmio-elf",
        metadata={"fixture": True, "synthetic": True, "owned": True})
    analysis = AngrAnalyzer(memory_map=memory_map).analyze(artifact)
    behavior = NetworkXGraphRepository(metadata={"fixture": True})
    ingest_analysis_result(analysis, behavior)
    sample = VulnerabilitySample.model_validate_json((root / "tests" / "fixtures" / "knowledge" /
        "synthetic_arm_vulnerability.json").read_text(encoding="utf-8"))
    knowledge = NetworkXKnowledgeGraphRepository.from_bundle(VulnerabilityKnowledgeBuilder().build(sample))
    candidates = CrossGraphCandidateSearcher().search(behavior, knowledge,
        architecture=Architecture.ARM, start_node_id="synthetic-arm-mmio:function:00010030", max_hops=2)
    candidate = next(item for item in candidates
        if behavior.get_edge(item.behavior_path.edge_ids[-1]).relation is RelationType.MMIO_WRITE)
    fixture = json.loads((root / "tests" / "fixtures" / "verification" /
        "type2_arm_mmio_interaction.json").read_text(encoding="utf-8"))
    interaction = CrossLayerInteraction.model_validate(fixture["interaction"])
    verification_input = InteractionVerificationInput.model_validate(fixture["verification_input"])
    return (
        interaction,
        verification_input,
        candidate,
        behavior,
        knowledge,
        InMemoryEvidenceResolver(analysis.evidence),
    )


def build_demo_result():
    """Return the detached result and its explicitly typed input objects."""

    interaction, verification_input, candidate, behavior, knowledge, resolver = (
        build_demo_material()
    )
    result = InteractionVerificationPipeline().verify(
        interaction,
        verification_input,
        behavior,
        knowledge,
        resolver,
        legacy_candidate=candidate,
    )
    return interaction, candidate, result


def main() -> None:
    interaction, candidate, result = build_demo_result()
    print("ChipChain Phase 9A-R2 interaction verification demo")
    print(f"Interaction ID: {interaction.id}")
    print(f"Interaction Type: {interaction.interaction_type.value}")
    print(f"Direction: {interaction.direction.value}")
    print(f"Capability: {result.capability_status.value}")
    print(f"Legacy Candidate: {candidate.id}")
    for record in result.behavior_edge_verifications:
        print(f"Behavior Verification: {record.subject_id} = {record.status.value}")
    trigger = next(item for item in result.binding_verifications if item.subject_id.startswith("trigger_behavior:"))
    print(f"Trigger Behavior: {trigger.status.value}")
    print(
        "Cross-Layer Transition: "
        f"{result.required_fact_statuses[RequiredFactCategory.CROSS_LAYER_TRANSITION_SUPPORT].value}"
    )
    print(f"Entity Link: {result.entity_link_verifications[0].status.value}")
    print("Target Hardware Vulnerability: unknown")
    print("Condition Status: unknown")
    print(f"Evidence Support Score: {result.verification_score}")
    print(f"Verification Status: {result.verification_status.value}")
    location = result.location_findings[0]
    print(f"Location Role: {location.role.value}")
    print(f"Program Address: {location.instruction_address.value}")
    print(f"Hardware Address: {location.hardware_address.value}")
    print("Initiating Firmware Vulnerability: not required by Type II")
    print("Dynamic Verification: not implemented")
    print("This is not a verified attack chain.")


if __name__ == "__main__":
    main()
