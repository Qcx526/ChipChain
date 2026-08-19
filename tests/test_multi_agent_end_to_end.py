"""Phase 4B→8 owned ARM deterministic multi-agent end-to-end test."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("angr")
pytestmark = pytest.mark.angr


def test_arm_multi_agent_demo_preserves_fixed_order_and_boundary() -> None:
    """Real ARM observations reach three offline agents without verification."""

    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [sys.executable, "examples/arm_multi_agent_demo.py"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "ChipChain Phase 8 ARM multi-agent demo" in completed.stdout
    assert "Architecture: arm" in completed.stdout
    assert "Evidence Analyst: evidence_incomplete" in completed.stdout
    assert "Security Reasoner: insufficient_context" in completed.stdout
    assert "Semantic Hypotheses: 1" in completed.stdout
    assert "Critic: revision_required" in completed.stdout
    assert "Final Status: insufficient_context" in completed.stdout
    assert (
        "Execution Order: evidence_analyst -> security_reasoner -> critic"
        in completed.stdout
    )
    assert "Unresolved Triggers: 1" in completed.stdout
    assert "Unresolved Preconditions: 1" in completed.stdout
    assert "This is not a verified attack chain." in completed.stdout
