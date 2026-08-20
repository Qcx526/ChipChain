"""Strict offline tests for untrusted QEMU plugin JSONL."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from chipchain.runtime.qemu import (
    QemuRawEventKind,
    QemuRawTraceError,
    QemuRawTraceParser,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "qemu_raw"
VALID = FIXTURES / "valid_arm_mmio_trace.jsonl"


def _records() -> list[dict[str, object]]:
    return [json.loads(line) for line in VALID.read_text(encoding="utf-8").splitlines()]


def _write(tmp_path: Path, records: list[dict[str, object]]) -> Path:
    path = tmp_path / "raw.jsonl"
    path.write_text(
        "\n".join(json.dumps(item, separators=(",", ":")) for item in records) + "\n",
        encoding="utf-8",
    )
    return path


def test_valid_raw_trace_parses_header_events_end_and_sha256() -> None:
    parsed = QemuRawTraceParser().parse(VALID)

    assert parsed.header.target_name == "arm"
    assert parsed.header.plugin_build_api_version == 6
    assert parsed.header.plugin_api_min == 2
    assert parsed.header.plugin_api_current == 6
    assert parsed.header.system_emulation is True
    assert parsed.header.smp_vcpus == 1
    assert [item.sequence_index for item in parsed.events] == [0, 1]
    assert parsed.events[0].event_kind is QemuRawEventKind.INSTRUCTION_EXEC
    assert parsed.events[1].event_kind is QemuRawEventKind.MMIO_WRITE
    assert parsed.end.clean_shutdown is True
    assert parsed.artifact_sha256 == hashlib.sha256(VALID.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    "fixture",
    [
        "malformed_json.jsonl",
        "malformed_missing_end.jsonl",
        "malformed_sequence_gap.jsonl",
    ],
)
def test_malformed_raw_fixtures_fail_closed(fixture: str) -> None:
    with pytest.raises(QemuRawTraceError):
        QemuRawTraceParser().parse(FIXTURES / fixture)


def test_missing_or_duplicate_header_is_rejected(tmp_path: Path) -> None:
    records = _records()
    with pytest.raises(QemuRawTraceError, match="header must be the first"):
        QemuRawTraceParser().parse(_write(tmp_path, records[1:]))

    records = _records()
    records.insert(1, dict(records[0]))
    with pytest.raises(QemuRawTraceError, match="exactly one header"):
        QemuRawTraceParser().parse(_write(tmp_path, records))


def test_trailing_record_after_end_is_rejected(tmp_path: Path) -> None:
    records = _records()
    records.append(dict(records[1]))
    with pytest.raises(QemuRawTraceError, match="end must be the final"):
        QemuRawTraceParser().parse(_write(tmp_path, records))


@pytest.mark.parametrize(
    "field,value",
    [
        ("target_name", "aarch64"),
        ("system_emulation", False),
        ("smp_vcpus", 2),
    ],
)
def test_unsupported_header_runtime_is_rejected(
    tmp_path: Path, field: str, value: object
) -> None:
    records = _records()
    records[0][field] = value
    with pytest.raises(QemuRawTraceError):
        QemuRawTraceParser().parse(_write(tmp_path, records))


@pytest.mark.parametrize(
    "mutation",
    [
        {"event_kind": "memory_access"},
        {"event_kind": "dma_write"},
        {"physical_address": None},
        {"is_io": False},
        {"vulnerability_id": "CVE-NOT-ALLOWED"},
    ],
)
def test_invalid_or_security_enriched_mmio_event_is_rejected(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    records = _records()
    records[2].update(mutation)
    with pytest.raises(QemuRawTraceError):
        QemuRawTraceParser().parse(_write(tmp_path, records))


def test_duplicate_sequence_is_rejected(tmp_path: Path) -> None:
    records = _records()
    records[2]["sequence_index"] = 0
    with pytest.raises(QemuRawTraceError):
        QemuRawTraceParser().parse(_write(tmp_path, records))


@pytest.mark.parametrize(
    "mutation",
    [
        {"event_count": 3},
        {"last_sequence_index": 0},
        {"clean_shutdown": False},
        {"diagnostic": "not allowed"},
    ],
)
def test_raw_end_contract_fails_closed(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    records = _records()
    records[-1].update(mutation)
    with pytest.raises(QemuRawTraceError):
        QemuRawTraceParser().parse(_write(tmp_path, records))
