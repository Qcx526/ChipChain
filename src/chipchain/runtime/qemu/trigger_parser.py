"""Strict parser for the isolated Phase 9C trigger-sequence JSONL format."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from chipchain.runtime.qemu.errors import QemuTriggerRawTraceError
from chipchain.runtime.qemu.trigger_models import (
    QemuParsedTriggerTrace,
    QemuTriggerRawEnd,
    QemuTriggerRawHeader,
    QemuTriggerRawInstructionEvent,
)


class QemuTriggerRawTraceParser:
    """Read and validate one complete header/events/end raw artifact."""

    def parse(self, path: str | Path) -> QemuParsedTriggerTrace:
        """Preserve exact raw SHA-256 and reject every incomplete trace."""

        source = Path(path)
        try:
            raw_bytes = source.read_bytes()
        except OSError as exc:
            raise QemuTriggerRawTraceError(
                "QEMU trigger raw trace could not be read"
            ) from exc
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise QemuTriggerRawTraceError(
                "QEMU trigger raw trace must be UTF-8"
            ) from exc
        lines = text.splitlines()
        if not lines:
            raise QemuTriggerRawTraceError("QEMU trigger raw trace is empty")
        if any(not line.strip() for line in lines):
            raise QemuTriggerRawTraceError(
                "QEMU trigger raw trace cannot contain blank records"
            )
        records: list[dict[str, object]] = []
        for line_number, line in enumerate(lines, start=1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise QemuTriggerRawTraceError(
                    f"malformed trigger JSON at line {line_number}"
                ) from exc
            if not isinstance(value, dict):
                raise QemuTriggerRawTraceError(
                    f"trigger record at line {line_number} must be an object"
                )
            records.append(value)
        if records[0].get("record_type") != "header":
            raise QemuTriggerRawTraceError("trigger header must be first")
        if records[-1].get("record_type") != "end":
            raise QemuTriggerRawTraceError("trigger end must be final")
        if sum(item.get("record_type") == "header" for item in records) != 1:
            raise QemuTriggerRawTraceError("trigger trace requires one header")
        if sum(item.get("record_type") == "end" for item in records) != 1:
            raise QemuTriggerRawTraceError("trigger trace requires one end")
        if any(item.get("record_type") != "event" for item in records[1:-1]):
            raise QemuTriggerRawTraceError("trigger middle records must be events")
        try:
            return QemuParsedTriggerTrace.create(
                header=QemuTriggerRawHeader.model_validate(records[0]),
                events=[
                    QemuTriggerRawInstructionEvent.model_validate(item)
                    for item in records[1:-1]
                ],
                end=QemuTriggerRawEnd.model_validate(records[-1]),
                raw_trace_sha256=hashlib.sha256(raw_bytes).hexdigest(),
            )
        except (ValidationError, ValueError) as exc:
            raise QemuTriggerRawTraceError(
                "QEMU trigger raw trace contract validation failed"
            ) from exc
