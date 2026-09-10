"""Bounded JSON transport checks, not model-output repair."""

import json

from pydantic import JsonValue


def utf8_snapshot(text: str, limit: int) -> bytes:
    """Encode one exact string snapshot, rejecting non-text/oversize/surrogates."""

    if type(text) is not str or not text or len(text) > limit:
        raise ValueError("invalid text size/type")
    data = text.encode("utf-8", errors="strict")
    if len(data) > limit:
        raise ValueError("UTF-8 byte limit exceeded")
    return data


def _unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_number(value: str) -> None:
    # The v1 wire schema has integers and explicit hexadecimal strings only.
    raise ValueError("floating/nonfinite JSON numbers are outside this contract")


def strict_json_object(text: str, *, limit: int) -> dict[str, JsonValue]:
    """Reject duplicate keys, floats, nonfinite numbers, excess depth and junk."""

    utf8_snapshot(text, limit)
    value = json.loads(text, object_pairs_hook=_unique_object,
        parse_constant=_reject_number, parse_float=_reject_number)
    if not isinstance(value, dict):
        raise ValueError("expected exactly one JSON object")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 32:
            raise ValueError("JSON nesting limit exceeded")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value
