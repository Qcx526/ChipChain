"""Create, query, save, and reload the synthetic ARM behavior graph."""

from __future__ import annotations

import argparse
from pathlib import Path

from chipchain.graph import NetworkXGraphRepository, build_arm_demo_graph
from chipchain.models import Architecture, Layer


def build_parser() -> argparse.ArgumentParser:
    """Create command-line arguments for the graph demo."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/arm_graph_demo.json"),
        help="JSON snapshot destination.",
    )
    return parser


def query_and_print(repository: NetworkXGraphRepository, label: str) -> None:
    """Run the firmware-to-register query and print its first stable result."""

    paths = repository.find_paths(
        "fixture_parse_command",
        target_id="fixture_debug_ctrl",
        architecture=Architecture.ARM,
        max_hops=3,
        allowed_layers={
            Layer.FIRMWARE,
            Layer.INTERFACE,
            Layer.DRIVER,
            Layer.HARDWARE,
        },
    )
    if not paths:
        raise RuntimeError("the ARM fixture graph did not produce its expected path")
    path = paths[0]
    print(label)
    print(f"Node path: {' -> '.join(path.node_ids)}")
    print(f"Edge path: {' -> '.join(path.edge_ids)}")
    print(f"Hop count: {path.hop_count}")


def main() -> int:
    """Execute the deterministic graph persistence demonstration."""

    args = build_parser().parse_args()
    repository = build_arm_demo_graph()
    query_and_print(repository, "Before save")
    repository.save(args.output)
    print(f"Saved graph: {args.output.resolve()}")

    restored = NetworkXGraphRepository.load(args.output)
    query_and_print(restored, "After reload")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
