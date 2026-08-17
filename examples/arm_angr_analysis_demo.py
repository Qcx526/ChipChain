"""Analyze the owned synthetic ARM ELF and query its recovered call path."""

from __future__ import annotations

from pathlib import Path

from chipchain.analysis import AngrAnalyzer, ProgramArtifact, ingest_analysis_result
from chipchain.graph import NetworkXGraphRepository
from chipchain.models import Architecture, Layer


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = (
    REPOSITORY_ROOT
    / "tests"
    / "fixtures"
    / "angr"
    / "arm_call_chain"
    / "arm_call_chain.elf"
)
ARTIFACT_ID = "synthetic-arm-call-chain"


def main() -> None:
    """Run ARM ELF → AngrAnalyzer → repository → GraphPath."""

    artifact = ProgramArtifact(
        id=ARTIFACT_ID,
        architecture=Architecture.ARM,
        artifact_type="elf",
        path=str(FIXTURE_PATH),
        fixture_identifier="synthetic-arm-call-chain-elf",
        metadata={"fixture": True, "synthetic": True, "owned": True},
    )
    result = AngrAnalyzer().analyze(artifact)
    repository = NetworkXGraphRepository()
    ingest_analysis_result(result, repository)
    paths = repository.find_paths(
        f"{ARTIFACT_ID}:function:00010028",
        target_id=f"{ARTIFACT_ID}:function:00010000",
        architecture=Architecture.ARM,
        max_hops=3,
        allowed_layers={Layer.FIRMWARE},
    )

    print(f"Artifact: {artifact.id}")
    print(f"Architecture: {result.architecture.value}")
    print(f"Functions recovered: {len(result.nodes)}")
    print(f"Calls recovered: {len(result.edges)}")
    print(f"Unresolved calls: {result.metadata['unresolved_calls']}")
    print(f"Evidence count: {len(result.evidence)}")
    if not paths:
        raise RuntimeError("expected synthetic call path was not recovered")
    print("GraphPath: " + " -> ".join(paths[0].node_ids))


if __name__ == "__main__":
    main()
