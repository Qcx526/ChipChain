"""Offline strict parsing for the isolated trigger-sequence raw v1."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from chipchain.runtime.qemu import (
    QemuTriggerRawTraceError,
    QemuTriggerRawTraceParser,
)


ROOT = Path(__file__).resolve().parents[1]
VALID = (
    ROOT
    / "tests"
    / "fixtures"
    / "qemu_trigger_raw"
    / "valid_arm_a32_trigger_trace.jsonl"
)


def _records() -> list[dict[str, object]]:
    return [json.loads(line) for line in VALID.read_text("utf-8").splitlines()]


def _write(tmp_path: Path, records: list[dict[str, object]]) -> Path:
    path = tmp_path / "trigger.jsonl"
    path.write_text(
        "\n".join(json.dumps(item, separators=(",", ":")) for item in records)
        + "\n",
        encoding="utf-8",
    )
    return path


def test_valid_trigger_trace_preserves_exact_raw_hash_and_contract() -> None:
    parsed = QemuTriggerRawTraceParser().parse(VALID)

    assert parsed.header.format == "chipchain_qemu_trigger_sequence_trace"
    assert parsed.header.format_version == 1
    assert parsed.header.target_name == "arm"
    assert parsed.header.smp_vcpus == 1
    assert parsed.end.clean_shutdown is True
    assert [item.sequence_index for item in parsed.events] == list(range(8))
    assert parsed.events[1].instruction_bytes == "0100a0e3"
    assert parsed.raw_trace_sha256 == hashlib.sha256(VALID.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    ("record_index", "field", "value"),
    [
        (0, "target_name", "aarch64"),
        (0, "system_emulation", False),
        (0, "smp_vcpus", 2),
        (1, "vcpu_index", 1),
        (1, "instruction_size", 0),
        (1, "instruction_bytes", "0400"),
        (1, "instruction_bytes", "040000EB"),
        (1, "instruction_bytes", "zzzzzzzz"),
        (1, "vulnerability_id", "not-allowed"),
        (-1, "clean_shutdown", False),
        (-1, "event_count", 7),
    ],
)
def test_invalid_scope_bytes_extra_fields_and_integrity_fail_closed(
    tmp_path: Path, record_index: int, field: str, value: object
) -> None:
    records = _records()
    records[record_index][field] = value
    with pytest.raises(QemuTriggerRawTraceError):
        QemuTriggerRawTraceParser().parse(_write(tmp_path, records))


def test_missing_end_duplicate_or_out_of_order_index_fails_closed(tmp_path: Path) -> None:
    records = _records()
    with pytest.raises(QemuTriggerRawTraceError, match="end must be final"):
        QemuTriggerRawTraceParser().parse(_write(tmp_path, records[:-1]))

    records = _records()
    records[2]["sequence_index"] = 0
    with pytest.raises(QemuTriggerRawTraceError):
        QemuTriggerRawTraceParser().parse(_write(tmp_path, records))

    records = _records()
    records[1], records[2] = records[2], records[1]
    with pytest.raises(QemuTriggerRawTraceError):
        QemuTriggerRawTraceParser().parse(_write(tmp_path, records))


def test_parsed_trace_semantic_mutation_is_rejected_on_detached_revalidation() -> None:
    parsed = QemuTriggerRawTraceParser().parse(VALID)
    parsed.events[1].__dict__["instruction_bytes"] = "0200a0e3"

    with pytest.raises(ValueError, match="deterministic"):
        type(parsed).model_validate(parsed.model_dump(mode="json"))
