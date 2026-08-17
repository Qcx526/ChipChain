"""Shared fixture loaders for domain model tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from chipchain.graph import NetworkXGraphRepository, build_arm_demo_graph

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
