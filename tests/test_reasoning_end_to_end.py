"""Phase 4B→7 owned ARM local-RAG and Mock-provider end-to-end test."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("angr")
pytestmark = pytest.mark.angr


def test_arm_rag_reasoning_demo_preserves_verification_boundary() -> None:
    """Real ARM observations reach an architecture-safe unresolved assessment."""

    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [sys.executable, "examples/arm_rag_reasoning_demo.py"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "ChipChain Phase 7 ARM RAG reasoning demo" in completed.stdout
    assert "Architecture: arm" in completed.stdout
    assert "arm-fixture-mmio-note" in completed.stdout
    assert "global-fixture-taxonomy-note" in completed.stdout
    assert "Excluded by architecture:\nriscv-distractor-note" in completed.stdout
    assert "Semantic Status: requires_verification" in completed.stdout
    assert "Unresolved Triggers: 1" in completed.stdout
    assert "Unresolved Preconditions: 1" in completed.stdout
    assert "Supporting Behavior Evidence:" in completed.stdout
    assert "Supporting Knowledge Chunks:" in completed.stdout
    assert "This is not a verified attack chain." in completed.stdout
