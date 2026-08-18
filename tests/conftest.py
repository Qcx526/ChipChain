"""Shared fixture loaders for domain model tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from chipchain.analysis import DemoAnalyzer, ProgramAnalysisResult, ProgramArtifact
from chipchain.graph import NetworkXGraphRepository, build_arm_demo_graph
from chipchain.knowledge import (
    KnowledgeGraphBundle,
    NetworkXKnowledgeGraphRepository,
    VulnerabilityKnowledgeBuilder,
)
from chipchain.models import VulnerabilitySample

FIXTURE_DIRECTORY = Path(__file__).parent / "fixtures"


def load_fixture_data(name: str) -> dict[str, Any]:
    """Load a JSON fixture into a fresh dictionary."""

    path = FIXTURE_DIRECTORY / name
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def arm_chain_data() -> dict[str, Any]:
    """Return the valid ARM candidate-chain fixture data."""

    return load_fixture_data("valid_arm_chain.json")


@pytest.fixture
def arm_vulnerability_data() -> dict[str, Any]:
    """Return the valid ARM vulnerability fixture data."""

    return load_fixture_data("valid_arm_vulnerability.json")


@pytest.fixture
def arm_demo_graph() -> NetworkXGraphRepository:
    """Return a fresh synthetic ARM MultiDiGraph repository."""

    return build_arm_demo_graph()


@pytest.fixture
def synthetic_arm_knowledge_sample() -> VulnerabilitySample:
    """Load the owned Phase 5 ARM vulnerability knowledge fixture."""

    return VulnerabilitySample.model_validate(
        load_fixture_data("knowledge/synthetic_arm_vulnerability.json")
    )


@pytest.fixture
def synthetic_arm_knowledge_bundle(
    synthetic_arm_knowledge_sample: VulnerabilitySample,
) -> KnowledgeGraphBundle:
    """Build a fresh deterministic bundle from the owned fixture."""

    return VulnerabilityKnowledgeBuilder().build(synthetic_arm_knowledge_sample)


@pytest.fixture
def synthetic_arm_knowledge_repository(
    synthetic_arm_knowledge_bundle: KnowledgeGraphBundle,
) -> NetworkXKnowledgeGraphRepository:
    """Return a fresh independent knowledge repository."""

    return NetworkXKnowledgeGraphRepository.from_bundle(
        synthetic_arm_knowledge_bundle
    )


@pytest.fixture
def demo_program_spec_path() -> Path:
    """Return the auditable ARM DemoAnalyzer input fixture path."""

    return FIXTURE_DIRECTORY / "program_analysis" / "arm_demo_program.json"


@pytest.fixture
def demo_program_spec_data(demo_program_spec_path: Path) -> dict[str, Any]:
    """Return a fresh dictionary containing the demo program specification."""

    return json.loads(demo_program_spec_path.read_text(encoding="utf-8"))


@pytest.fixture
def demo_program_artifact(demo_program_spec_path: Path) -> ProgramArtifact:
    """Return the ProgramArtifact used by the deterministic DemoAnalyzer."""

    return ProgramArtifact(
        id="fixture-arm-program",
        architecture="arm",
        artifact_type="fixture",
        path=str(demo_program_spec_path),
        fixture_identifier="fixture-arm-demo-program-spec",
        metadata={"fixture": True, "real_program": False},
    )


@pytest.fixture
def demo_analysis_result(
    demo_program_artifact: ProgramArtifact,
) -> ProgramAnalysisResult:
    """Analyze the ARM program fixture into a fresh validated result."""

    return DemoAnalyzer().analyze(demo_program_artifact)
