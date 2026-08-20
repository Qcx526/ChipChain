"""Strict QMP command/response handling for same-process topology capture."""

from __future__ import annotations

import json

from chipchain.runtime.qemu.errors import QemuQmpError


_CAPABILITIES_ID = "chipchain-capabilities"
_TOPOLOGY_ID = "chipchain-topology"
_CONTINUE_ID = "chipchain-cont"


def build_qmp_command_stream() -> str:
    """Return newline-delimited QMP commands in the required paused-run order."""

    commands = (
        {"execute": "qmp_capabilities", "id": _CAPABILITIES_ID},
        {
            "execute": "human-monitor-command",
            "arguments": {"command-line": "info mtree -f"},
            "id": _TOPOLOGY_ID,
        },
        {"execute": "cont", "id": _CONTINUE_ID},
    )
    return "".join(
        json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
        for item in commands
    )


def parse_qmp_topology_response(stdout: str) -> str:
    """Validate greeting and ID-matched responses, then return raw HMP text."""

    records: list[dict[str, object]] = []
    for line_number, line in enumerate(stdout.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise QemuQmpError(
                f"QMP stdout contains malformed JSON at line {line_number}"
            ) from exc
        if not isinstance(value, dict):
            raise QemuQmpError("QMP stdout records must be JSON objects")
        records.append(value)
    if not records or not isinstance(records[0].get("QMP"), dict):
        raise QemuQmpError("QMP greeting is missing or malformed")

    responses: dict[str, tuple[int, dict[str, object]]] = {}
    for index, record in enumerate(records[1:], start=1):
        response_id = record.get("id")
        if response_id is None:
            if "event" in record:
                continue
            raise QemuQmpError("unidentified non-event QMP response")
        if not isinstance(response_id, str):
            raise QemuQmpError("QMP response ID must be a string")
        if response_id in responses:
            raise QemuQmpError(f"duplicate QMP response ID: {response_id}")
        responses[response_id] = (index, record)

    required = (_CAPABILITIES_ID, _TOPOLOGY_ID, _CONTINUE_ID)
    if set(responses) != set(required):
        raise QemuQmpError("QMP stdout contains an unexpected response ID")
    if any(item not in responses for item in required):
        raise QemuQmpError("one or more required QMP responses are missing")
    if [responses[item][0] for item in required] != sorted(
        responses[item][0] for item in required
    ):
        raise QemuQmpError("QMP responses violate topology-before-cont order")
    for response_id in required:
        response = responses[response_id][1]
        if "error" in response or "return" not in response:
            raise QemuQmpError(f"QMP command failed: {response_id}")
    if not isinstance(responses[_CAPABILITIES_ID][1]["return"], dict):
        raise QemuQmpError("QMP capabilities response must return an object")
    if not isinstance(responses[_CONTINUE_ID][1]["return"], dict):
        raise QemuQmpError("QMP cont response must return an object")
    topology = responses[_TOPOLOGY_ID][1]["return"]
    if not isinstance(topology, str) or not topology:
        raise QemuQmpError("QMP topology response must be a non-empty string")
    return topology
