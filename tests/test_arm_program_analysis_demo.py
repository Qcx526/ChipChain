"""Integration test for the documented Phase 3 demo script."""

from __future__ import annotations

import subprocess
import sys


def test_arm_program_analysis_demo_prints_observations_and_graph_path() -> None:
    """The example should report behavior facts without security conclusions."""

    result = subprocess.run(
        [sys.executable, "examples/arm_program_analysis_demo.py"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Discovered functions: 3" in result.stdout
    assert "Discovered interfaces: 1" in result.stdout
    assert "Call relations: 1" in result.stdout
    assert "MMIO accesses: 1" in result.stdout
    assert "Evidence count: 4" in result.stdout
    assert (
        "Node path: fixture_parse_command -> fixture_ioctl -> "
        "fixture_driver_ioctl -> fixture_debug_ctrl"
    ) in result.stdout
    assert "Hop count: 3" in result.stdout
    assert "Vulnerability Found" not in result.stdout
    assert "Exploit Confirmed" not in result.stdout
