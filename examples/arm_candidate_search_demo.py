"""Run the owned ARM MMIO fixture through exact Phase 6 correlation."""

from __future__ import annotations

from pathlib import Path

from chipchain.analysis import (
    AngrAnalyzer,
    MemoryMap,
    ProgramArtifact,
    ingest_analysis_result,
)
from chipchain.candidate import CrossGraphCandidateSearcher
from chipchain.graph import NetworkXGraphRepository
from chipchain.knowledge import (
    NetworkXKnowledgeGraphRepository,
    VulnerabilityKnowledgeBuilder,
)
from chipchain.models import Architecture, Layer, RelationType, VulnerabilitySample


def main() -> None:
    """Print one unverified machine-code-to-knowledge structural candidate."""

    root = Path(__file__).resolve().parents[1]
    mmio_directory = root / "tests" / "fixtures" / "angr" / "arm_mmio"
    memory_map = MemoryMap.model_validate_json(
        (mmio_directory / "memory_map.json").read_text(encoding="utf-8")
    )
    artifact = ProgramArtifact(
        id="synthetic-arm-mmio",
        architecture=Architecture.ARM,
        artifact_type="elf",
        program_layer=Layer.DRIVER,
        path=str(mmio_directory / "arm_mmio.elf"),
        fixture_identifier="synthetic-arm-mmio-elf",
        metadata={"fixture": True, "synthetic": True, "owned": True},
    )
    analysis = AngrAnalyzer(memory_map=memory_map).analyze(artifact)
    behavior = NetworkXGraphRepository(metadata={"fixture": True})
    ingest_analysis_result(analysis, behavior)

    sample_path = (
        root
        / "tests"
        / "fixtures"
        / "knowledge"
        / "synthetic_arm_vulnerability.json"
    )
    sample = VulnerabilitySample.model_validate_json(
        sample_path.read_text(encoding="utf-8")
    )
    knowledge = NetworkXKnowledgeGraphRepository.from_bundle(
        VulnerabilityKnowledgeBuilder().build(sample)
    )
    candidates = CrossGraphCandidateSearcher().search(
        behavior,
        knowledge,
        architecture=Architecture.ARM,
        start_node_id="synthetic-arm-mmio:function:00010030",
        max_hops=2,
    )
    candidate = next(
        item
        for item in candidates
        if behavior.get_edge(item.behavior_path.edge_ids[-1]).relation
        is RelationType.MMIO_WRITE
    )

    print("ChipChain Phase 6 candidate correlation demo")
    print(f"Architecture: {candidate.architecture.value}")
    print("Behavior Path:")
    print(behavior.get_node(candidate.behavior_path.node_ids[0]).name)
    for edge_id, node_id in zip(
        candidate.behavior_path.edge_ids,
        candidate.behavior_path.node_ids[1:],
        strict=True,
    ):
        print(f" -> {behavior.get_edge(edge_id).relation.value.upper()}")
        print(behavior.get_node(node_id).name)
    print("Entity Link:")
    print(f"Behavior Node: {candidate.entity_link.behavior_node_id}")
    print(f"Knowledge Node: {candidate.entity_link.knowledge_node_id}")
    print("Match Keys:")
    for key in candidate.entity_link.match_keys:
        print(key)
    print(f"Knowledge Candidate: {candidate.knowledge_vulnerability_id}")
    print(f"Trigger Count: {len(candidate.trigger_node_ids)}")
    print(f"Precondition Count: {len(candidate.precondition_node_ids)}")
    print(f"Impact Count: {len(candidate.impact_node_ids)}")
    print("Candidate Status: unverified correlation")
    print("This is not a verified attack chain.")


if __name__ == "__main__":
    main()
