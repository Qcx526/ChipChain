"""Strict QEMU FlatView, same-process QMP, and classification regressions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from chipchain.runtime.qemu import (
    QemuMemoryRegion,
    QemuMemoryRegionKind,
    QemuMemoryTopologyParser,
    QemuMemoryTopologySnapshot,
    QemuQmpError,
    QemuRawEvent,
    QemuTopologyClassificationError,
    QemuTopologyClassificationKind,
    QemuTopologyClassifier,
    QemuTopologyError,
    build_qmp_command_stream,
    parse_qmp_topology_response,
)


ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY = (
    ROOT
    / "tests"
    / "fixtures"
    / "qemu_topology"
    / "qemu-11.0.3-virt-cortex-a15-smp1-mtree-flat.txt"
)


def _snapshot(path: Path = TOPOLOGY) -> QemuMemoryTopologySnapshot:
    return QemuMemoryTopologyParser().parse(
        path,
        qemu_version="11.0.3",
        machine="virt",
        cpu="cortex-a15",
        vcpu_count=1,
    )


def _event(address: int, size: int = 1, kind: str = "memory_write") -> QemuRawEvent:
    return QemuRawEvent(
        sequence_index=3,
        vcpu_index=0,
        event_kind=kind,
        pc={"value": "0x40200008"},
        virtual_address={"value": hex(address)},
        physical_address={"value": hex(address)},
        access_size=size,
        plugin_is_io=False,
        plugin_device_name="RAM",
    )


def test_captured_qemu_11_flatview_parses_pl011_and_code_ram() -> None:
    snapshot = _snapshot()

    assert snapshot.address_space_name == "memory"
    assert snapshot.root_region_name == "system"
    assert snapshot.artifact_sha256 == hashlib.sha256(TOPOLOGY.read_bytes()).hexdigest()
    pl011 = next(item for item in snapshot.regions if item.start == 0x09000000)
    assert pl011.end == 0x09000FFF
    assert pl011.kind is QemuMemoryRegionKind.IO
    assert pl011.name == "pl011"
    assert any(
        item.kind is QemuMemoryRegionKind.RAM
        and item.start <= 0x40200000 <= item.end
        for item in snapshot.regions
    )


def test_topology_id_is_semantic_while_raw_sha_tracks_exact_artifact(
    tmp_path: Path,
) -> None:
    crlf = tmp_path / "topology.txt"
    crlf.write_bytes(TOPOLOGY.read_bytes().replace(b"\n", b"\r\n"))

    first = _snapshot()
    second = _snapshot(crlf)

    assert first.id == second.id
    assert first.artifact_sha256 != second.artifact_sha256


def test_unique_io_and_ram_classification_are_distinct() -> None:
    classifier = QemuTopologyClassifier()
    snapshot = _snapshot()

    io = classifier.classify(_event(0x09000000), snapshot)
    ram = classifier.classify(_event(0x4020001C, 4, "memory_read"), snapshot)

    assert io.kind is QemuTopologyClassificationKind.IO
    assert io.region is not None and io.region.name == "pl011"
    assert ram.kind is QemuTopologyClassificationKind.RAM


def test_boundary_crossing_and_overflow_fail_closed_as_unknown() -> None:
    classifier = QemuTopologyClassifier()
    snapshot = _snapshot()

    boundary = classifier.classify(_event(0x09000FFF, 2), snapshot)
    overflow = classifier.classify(_event((1 << 64) - 1, 2), snapshot)

    assert boundary.kind is QemuTopologyClassificationKind.UNKNOWN
    assert boundary.reason == "crosses_region_boundary"
    assert overflow.kind is QemuTopologyClassificationKind.UNKNOWN
    assert overflow.reason == "address_overflow"


def test_ambiguous_topology_is_rejected() -> None:
    original = _snapshot()
    overlapping = QemuMemoryRegion(
        start=0x09000000,
        end=0x090000FF,
        kind="ram",
        name="ambiguous-fixture-overlap",
        priority=0,
    )
    ambiguous = QemuMemoryTopologySnapshot.create(
        qemu_version=original.qemu_version,
        machine=original.machine,
        cpu=original.cpu,
        vcpu_count=original.vcpu_count,
        root_region_name=original.root_region_name,
        regions=[*original.regions, overlapping],
        artifact_sha256=original.artifact_sha256,
    )

    with pytest.raises(QemuTopologyClassificationError, match="ambiguous"):
        QemuTopologyClassifier().classify(_event(0x09000000), ambiguous)


@pytest.mark.parametrize(
    "text",
    [
        "not a FlatView\n",
        "FlatView #0\n AS \"memory\", root: system\n",
        (
            "FlatView #0\n AS \"memory\", root: system\n"
            " Root memory region: system\n malformed region\n"
        ),
        (
            "FlatView #0\n AS \"memory\", root: system\n"
            " Root memory region: system\n"
            "  0000000000000000-0000000000000fff (prio 0, i/o): one\n\n"
            "FlatView #1\n AS \"memory\", root: other\n"
            " Root memory region: other\n"
            "  0000000000001000-0000000000001fff (prio 0, ram): two\n"
        ),
    ],
)
def test_malformed_or_non_unique_cpu_physical_flatview_is_rejected(
    tmp_path: Path, text: str
) -> None:
    path = tmp_path / "malformed.txt"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(QemuTopologyError):
        _snapshot(path)


def _qmp_stdout(topology: str, *, topology_id: str = "chipchain-topology") -> str:
    records = (
        {"QMP": {"version": {"qemu": {"major": 11}}, "capabilities": []}},
        {"return": {}, "id": "chipchain-capabilities"},
        {"return": topology, "id": topology_id},
        {"return": {}, "id": "chipchain-cont"},
    )
    return "".join(json.dumps(item) + "\n" for item in records)


def test_same_process_qmp_stream_and_id_matched_topology_response() -> None:
    stream = build_qmp_command_stream()
    topology = TOPOLOGY.read_text("utf-8")

    assert stream.index("qmp_capabilities") < stream.index(
        "human-monitor-command"
    ) < stream.index('"cont"')
    assert parse_qmp_topology_response(_qmp_stdout(topology)) == topology


def test_qmp_missing_or_wrong_topology_response_id_fails_closed() -> None:
    with pytest.raises(QemuQmpError, match="missing|unexpected"):
        parse_qmp_topology_response(
            _qmp_stdout(TOPOLOGY.read_text("utf-8"), topology_id="wrong-id")
        )
