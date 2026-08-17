"""Integration tests for the synthetic ARM graph and demo script."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from chipchain.graph import NetworkXGraphRepository
from chipchain.models import Architecture, Layer


def test_arm_demo_graph_covers_required_fixture_layers(
    arm_demo_graph: NetworkXGraphRepository,
) -> None:
    """The main demo spans firmware, interface, driver, hardware, and impact."""

    nodes = arm_demo_graph.list_nodes(architecture=Architecture.ARM)

    assert {node.layer for node in nodes} == {
        Layer.FIRMWARE,
        Layer.INTERFACE,
        Layer.DRIVER,
        Layer.HARDWARE,
        Layer.IMPACT,
    }
    assert arm_demo_graph.metadata == {
        "sample_type": "fixture",
        "source": "chipchain-arm-graph-fixture",
        "real_vulnerability": False,
    }
    assert all(node.metadata.get("fixture") is True for node in nodes)


def test_demo_script_queries_saves_and_reloads(tmp_path: Path) -> None:
    """The documented example should print equal paths before and after reload."""

    snapshot_path = tmp_path / "arm-demo.json"
    result = subprocess.run(
        [
            sys.executable,
            "examples/arm_graph_demo.py",
            "--output",
            str(snapshot_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert snapshot_path.exists()
    assert "Before save" in result.stdout
    assert "After reload" in result.stdout
    assert result.stdout.count("Hop count: 3") == 2
    assert result.stdout.count(
        "Node path: fixture_parse_command -> fixture_ioctl -> "
        "fixture_driver_ioctl -> fixture_debug_ctrl"
    ) == 2
