"""V2 deterministic JSON identity; independent of historical identity formats."""

import hashlib
import json
import math
import re

from pydantic import JsonValue


def canonical_json_bytes(payload: JsonValue) -> bytes:
    """Encode native JSON values as sorted, compact UTF-8 JSON.

    Object order is ignored; array order and numeric representation are retained.
    Reject non-string keys, non-finite floats, cycles, and implicit conversions.
    Models must be explicitly converted with ``model_dump(mode="json")`` first.
    """

    active: set[int] = set()

    def validate(value: object) -> None:
        if value is None or type(value) in (str, bool, int):
            return
        if type(value) is float:
            if not math.isfinite(value):
                raise ValueError("identity payload requires finite JSON numbers")
            return
        if not isinstance(value, (dict, list)) or type(value) not in (dict, list):
            raise ValueError("identity payload requires native JSON values")
        if id(value) in active:
            raise ValueError("identity payload cannot contain cycles")
        active.add(id(value))
        if isinstance(value, dict):
            if any(type(key) is not str for key in value):
                raise ValueError("identity object keys must be strings")
            children = value.values()
        else:
            children = value
        for child in children:
            validate(child)
        active.remove(id(value))

    validate(payload)
    return json.dumps(
        payload, sort_keys=True, ensure_ascii=False,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def deterministic_id(namespace: str, payload: JsonValue) -> str:
    """Return ``namespace:sha256`` for an explicitly versioned V2 namespace."""

    if not isinstance(namespace, str) or re.fullmatch(
        r"[a-z][a-z0-9._-]*", namespace
    ) is None:
        raise ValueError("identity namespace must be a lowercase stable token")
    return f"{namespace}:{hashlib.sha256(canonical_json_bytes(payload)).hexdigest()}"
