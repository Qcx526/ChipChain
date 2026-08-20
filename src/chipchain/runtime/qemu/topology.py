"""Parse and classify QEMU 11.0.3 resolved FlatView topology artifacts."""

from __future__ import annotations

import hashlib
import re
from enum import Enum
from pathlib import Path

from pydantic import Field

from chipchain.models.common import DomainModel, Identifier
from chipchain.runtime.qemu.errors import (
    QemuTopologyClassificationError,
    QemuTopologyError,
)
from chipchain.runtime.qemu.models import (
    QemuMemoryRegion,
    QemuMemoryRegionKind,
    QemuMemoryTopologySnapshot,
    QemuRawEvent,
    QemuRawEventKind,
)


_FLAT_VIEW = re.compile(r"^FlatView #[0-9]+$")
_ADDRESS_SPACE = re.compile(
    r'^ AS "(?P<name>[^"\r\n]+)", root: (?P<root>[^,\r\n]+)'
    r'(?:, alias (?P<alias>[^\r\n]+))?$'
)
_ROOT = re.compile(r"^ Root memory region: (?P<root>[^\r\n]+)$")
_REGION = re.compile(
    r"^  (?P<start>[0-9a-f]{16})-(?P<end>[0-9a-f]{16}) "
    r"\(prio (?P<priority>-?[0-9]+), "
    r"(?P<nonvolatile>nv-)?(?P<kind>ram|ramd|i/o|rom|romd|container)\): "
    r"(?P<name>[^@\r\n]+?)(?: @(?P<offset>[0-9a-f]{16}))?$"
)
_MAX_ADDRESS = (1 << 64) - 1


class QemuTopologyClassificationKind(str, Enum):
    """Fail-closed result of resolving one raw access against topology."""

    IO = "io"
    RAM = "ram"
    UNKNOWN = "unknown"


class QemuTopologyClassification(DomainModel):
    """Classification result with an optional uniquely resolved region."""

    kind: QemuTopologyClassificationKind
    reason: Identifier
    region: QemuMemoryRegion | None = None


class QemuMemoryTopologyParser:
    """Strictly parse QEMU `info mtree -f` and select AS `memory` uniquely."""

    def parse(
        self,
        path: str | Path,
        *,
        qemu_version: str,
        machine: str,
        cpu: str,
        vcpu_count: int,
    ) -> QemuMemoryTopologySnapshot:
        """Parse raw artifact bytes and retain their actual SHA-256."""

        source = Path(path)
        try:
            raw_bytes = source.read_bytes()
        except OSError as exc:
            raise QemuTopologyError("QEMU topology artifact could not be read") from exc
        return self.parse_bytes(
            raw_bytes,
            qemu_version=qemu_version,
            machine=machine,
            cpu=cpu,
            vcpu_count=vcpu_count,
        )

    def parse_bytes(
        self,
        raw_bytes: bytes,
        *,
        qemu_version: str,
        machine: str,
        cpu: str,
        vcpu_count: int,
    ) -> QemuMemoryTopologySnapshot:
        """Parse an exact HMP return payload without normalizing its bytes."""

        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise QemuTopologyError("QEMU topology artifact must be UTF-8") from exc
        views = self._parse_views(text)
        selected = [view for view in views if "memory" in view["address_spaces"]]
        if len(selected) != 1:
            raise QemuTopologyError(
                "QEMU topology must contain one unique CPU physical AS named memory"
            )
        view = selected[0]
        address_spaces = view["address_spaces"]
        root_by_as = view["root_by_as"]
        assert isinstance(address_spaces, list)
        assert isinstance(root_by_as, dict)
        root = root_by_as["memory"]
        printed_root = view["root"]
        if root != printed_root:
            raise QemuTopologyError("selected QEMU address-space root does not match FlatView")
        regions = view["regions"]
        assert isinstance(regions, list)
        return QemuMemoryTopologySnapshot.create(
            qemu_version=qemu_version,
            machine=machine,
            cpu=cpu,
            vcpu_count=vcpu_count,
            address_space_name="memory",
            root_region_name=root,
            regions=regions,
            artifact_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        )

    @staticmethod
    def _parse_views(text: str) -> list[dict[str, object]]:
        lines = text.splitlines()
        if not lines:
            raise QemuTopologyError("QEMU topology artifact is empty")
        views: list[dict[str, object]] = []
        current: dict[str, object] | None = None
        for line_number, line in enumerate(lines, start=1):
            if not line:
                if current is not None:
                    QemuMemoryTopologyParser._finish_view(current)
                    views.append(current)
                    current = None
                continue
            if _FLAT_VIEW.fullmatch(line):
                if current is not None:
                    raise QemuTopologyError(
                        f"missing FlatView separator before line {line_number}"
                    )
                current = {
                    "address_spaces": [],
                    "root_by_as": {},
                    "root": None,
                    "regions": [],
                }
                continue
            if current is None:
                raise QemuTopologyError(
                    f"unexpected QEMU topology content at line {line_number}"
                )
            if match := _ADDRESS_SPACE.fullmatch(line):
                name = match.group("name")
                address_spaces = current["address_spaces"]
                root_by_as = current["root_by_as"]
                assert isinstance(address_spaces, list)
                assert isinstance(root_by_as, dict)
                if name in root_by_as:
                    raise QemuTopologyError("duplicate QEMU address-space name")
                address_spaces.append(name)
                root_by_as[name] = match.group("alias") or match.group("root")
                continue
            if match := _ROOT.fullmatch(line):
                if current["root"] is not None:
                    raise QemuTopologyError("duplicate FlatView root")
                current["root"] = match.group("root")
                continue
            if match := _REGION.fullmatch(line):
                if current["root"] is None:
                    raise QemuTopologyError("QEMU region precedes FlatView root")
                raw_kind = match.group("kind")
                readonly = raw_kind in {"rom", "romd"}
                regions = current["regions"]
                assert isinstance(regions, list)
                regions.append(
                    QemuMemoryRegion(
                        start=int(match.group("start"), 16),
                        end=int(match.group("end"), 16),
                        kind=QemuMemoryRegionKind(raw_kind),
                        name=match.group("name").strip(),
                        priority=int(match.group("priority")),
                        nonvolatile=match.group("nonvolatile") is not None,
                        readonly=readonly,
                        offset_in_region=(
                            int(match.group("offset"), 16)
                            if match.group("offset") is not None
                            else None
                        ),
                    )
                )
                continue
            raise QemuTopologyError(
                f"unrecognized QEMU 11.0.3 FlatView line {line_number}"
            )
        if current is not None:
            QemuMemoryTopologyParser._finish_view(current)
            views.append(current)
        if not views:
            raise QemuTopologyError("QEMU topology contains no FlatView")
        return views

    @staticmethod
    def _finish_view(view: dict[str, object]) -> None:
        if not view["address_spaces"] or view["root"] is None or not view["regions"]:
            raise QemuTopologyError("QEMU FlatView is incomplete")


class QemuTopologyClassifier:
    """Promote only accesses wholly inside one unique resolved I/O leaf."""

    def classify(
        self,
        event: QemuRawEvent,
        topology: QemuMemoryTopologySnapshot,
    ) -> QemuTopologyClassification:
        """Classify a backend-local physical access without address heuristics."""

        if event.event_kind not in {
            QemuRawEventKind.MEMORY_READ,
            QemuRawEventKind.MEMORY_WRITE,
        }:
            raise QemuTopologyClassificationError(
                "topology classifier requires a raw memory event"
            )
        assert event.physical_address is not None
        assert event.access_size is not None
        start = int(event.physical_address.value, 16)
        if event.access_size - 1 > _MAX_ADDRESS - start:
            return QemuTopologyClassification(kind="unknown", reason="address_overflow")
        end = start + event.access_size - 1
        intersecting = [
            region
            for region in topology.regions
            if not (end < region.start or start > region.end)
        ]
        containing = [
            region
            for region in intersecting
            if region.start <= start and end <= region.end
        ]
        if len(containing) > 1 or (len(containing) == 1 and len(intersecting) > 1):
            raise QemuTopologyClassificationError(
                "physical access is ambiguous in resolved QEMU topology"
            )
        if not containing:
            reason = "crosses_region_boundary" if intersecting else "unmapped"
            return QemuTopologyClassification(kind="unknown", reason=reason)
        region = containing[0]
        if region.kind is QemuMemoryRegionKind.IO:
            return QemuTopologyClassification(
                kind="io", reason="unique_resolved_io_leaf", region=region
            )
        if region.kind in {
            QemuMemoryRegionKind.RAM,
            QemuMemoryRegionKind.RAM_DEVICE,
        }:
            return QemuTopologyClassification(
                kind="ram", reason="unique_resolved_ram_leaf", region=region
            )
        return QemuTopologyClassification(
            kind="unknown", reason="non_io_non_ram_region", region=region
        )
