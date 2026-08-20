"""Strict JSONL parsing for untrusted Phase 9B1 plugin output."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from chipchain.runtime.qemu.errors import QemuRawTraceError
from chipchain.runtime.qemu.models import (
    QemuParsedRawTrace,
    QemuRawEnd,
    QemuRawEvent,
    QemuRawHeader,
)


class QemuRawTraceParser:
    """Parse a complete header/events/end artifact and fail closed."""

    def parse(self, path: str | Path) -> QemuParsedRawTrace:
        """Read raw bytes, validate every JSON line, and retain SHA-256."""

        source = Path(path)
        try:
            raw_bytes = source.read_bytes()
        except OSError as exc:
            raise QemuRawTraceError("QEMU raw trace could not be read") from exc
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise QemuRawTraceError("QEMU raw trace must be UTF-8") from exc
        lines = text.splitlines()
        if not lines:
            raise QemuRawTraceError("QEMU raw trace is empty")
        if any(not line.strip() for line in lines):
            raise QemuRawTraceError("QEMU raw trace cannot contain blank records")

        records: list[dict[str, object]] = []
        for line_number, line in enumerate(lines, start=1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise QemuRawTraceError(
                    f"malformed QEMU JSON at line {line_number}"
                ) from exc
            if not isinstance(value, dict):
                raise QemuRawTraceError(
                    f"QEMU record at line {line_number} must be an object"
                )
            records.append(value)

        if records[0].get("record_type") != "header":
            raise QemuRawTraceError("QEMU raw header must be the first record")
        if records[-1].get("record_type") != "end":
            raise QemuRawTraceError("QEMU raw end must be the final record")
        if sum(item.get("record_type") == "header" for item in records) != 1:
            raise QemuRawTraceError("QEMU raw trace requires exactly one header")
        if sum(item.get("record_type") == "end" for item in records) != 1:
            raise QemuRawTraceError("QEMU raw trace requires exactly one end record")
        if any(item.get("record_type") != "event" for item in records[1:-1]):
            raise QemuRawTraceError("QEMU raw middle records must all be events")
        try:
            return QemuParsedRawTrace(
                header=QemuRawHeader.model_validate(records[0]),
                events=[QemuRawEvent.model_validate(item) for item in records[1:-1]],
                end=QemuRawEnd.model_validate(records[-1]),
                artifact_sha256=hashlib.sha256(raw_bytes).hexdigest(),
            )
        except ValidationError as exc:
            raise QemuRawTraceError("QEMU raw trace contract validation failed") from exc
