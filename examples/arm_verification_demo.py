"""Run the owned ARM ELF through Phase 9A objective verification."""

from __future__ import annotations

from pathlib import Path

from chipchain.analysis import AngrAnalyzer, MemoryMap, ProgramArtifact, ingest_analysis_result
from chipchain.candidate import CrossGraphCandidateSearcher
from chipchain.graph import NetworkXGraphRepository
from chipchain.knowledge import KnowledgeRelationType, NetworkXKnowledgeGraphRepository, VulnerabilityKnowledgeBuilder
from chipchain.models import Architecture, Layer, RelationType, VulnerabilitySample
from chipchain.reasoning import InMemoryEvidenceResolver
from chipchain.verification import CandidateVerificationPipeline


def main() -> None:
    """Print the conservative synthetic Phase 9A verification result."""

    root = Path(__file__).resolve().parents[1]
    mmio_dir = root / "tests" / "fixtures" / "angr" / "arm_mmio"
    memory_map = MemoryMap.model_validate_json(
        (mmio_dir / "memory_map.json").read_text(encoding="utf-8")
    )
    analysis = AngrAnalyzer(memory_map=memory_map).analyze(
        ProgramArtifact(
            id="synthetic-arm-mmio",
            architecture=Architecture.ARM,
            artifact_type="elf",
            program_layer=Layer.DRIVER,
            path=str(mmio_dir / "arm_mmio.elf"),
            fixture_identifier="synthetic-arm-mmio-elf",
            metadata={"fixture": True, "synthetic": True, "owned": True},
        )
    )
    behavior = NetworkXGraphRepository(metadata={"fixture": True})
    ingest_analysis_result(analysis, behavior)
    sample = VulnerabilitySample.model_validate_json(
        (root / "tests" / "fixtures" / "knowledge" / "synthetic_arm_vulnerability.json").read_text(encoding="utf-8")
    )
    knowledge = NetworkXKnowledgeGraphRepository.from_bundle(
        VulnerabilityKnowledgeBuilder().build(sample)
    )
    resolver = InMemoryEvidenceResolver.from_analysis_result(analysis)
    candidates = CrossGraphCandidateSearcher().search(
        behavior,
        knowledge,
        architecture=Architecture.ARM,
        start_node_id="synthetic-arm-mmio:function:00010030",
        max_hops=2,
    )
    candidate = next(
        item for item in candidates
        if behavior.get_edge(item.behavior_path.edge_ids[-1]).relation is RelationType.MMIO_WRITE
        and resolver.get(behavior.get_edge(item.behavior_path.edge_ids[-1]).evidence_ids[0]).address == "0x10008"
    )
    result = CandidateVerificationPipeline().verify(candidate, behavior, knowledge, resolver)
    target_record = next(
        item for item in result.knowledge_edge_verifications
        if item.metadata["relation"] == KnowledgeRelationType.TARGETS_RESOURCE.value
    )
    print("ChipChain Phase 9A synthetic ARM verification demo")
    print(f"Candidate: {result.candidate_id}")
    print("Behavior Edge Verification:")
    for edge, record in zip(
        [behavior.get_edge(item) for item in candidate.behavior_path.edge_ids],
        result.behavior_edge_verifications,
        strict=True,
    ):
        print(f"  {edge.relation.value.upper()}: {record.status.value}")
    print(f"Entity Link: {result.entity_link_verification.status.value}")
    print(f"TARGETS_RESOURCE: {target_record.status.value}")
    print(f"Trigger: {result.trigger_assessments[0].status.value}")
    print(f"Precondition: {result.precondition_assessments[0].status.value}")
    print(f"Architecture Rules: {', '.join(item.status.value for item in result.architecture_rule_verifications)}")
    print(f"Verification Score: {result.verification_score:.6f}")
    print(f"Candidate Verification Status: {result.verification_status.value}")
    print(f"Root Cause Candidate: {result.root_cause_localization.function_name}")
    print(f"MMIO sink instruction: {result.root_cause_localization.candidate_instruction_addresses[0].value}")
    print("Source Line: unavailable")
    print("Reason: requires further verification")
    print("Multi-Agent Advisory: unavailable in this objective-only demo")
    print("This is not a verified attack chain.")


if __name__ == "__main__":
    main()
