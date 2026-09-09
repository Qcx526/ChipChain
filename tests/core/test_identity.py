"""Canonical encoding and fail-closed identity payloads."""

import copy
import hashlib

import pytest

from chipchain.core import canonical_json_bytes, deterministic_id


def test_nested_key_order_canonical_bytes_and_id() -> None:
    first = {"z": [True, None, {"b": 2, "a": "测试"}], "a": 1}
    second = {"a": 1, "z": [True, None, {"a": "测试", "b": 2}]}
    expected = '{"a":1,"z":[true,null,{"a":"测试","b":2}]}'.encode("utf-8")
    assert canonical_json_bytes(first) == canonical_json_bytes(second) == expected
    assert deterministic_id("synthetic-v1", first) == (
        "synthetic-v1:" + hashlib.sha256(expected).hexdigest()
    )
    assert deterministic_id("synthetic-v1", first) == deterministic_id("synthetic-v1", second)


def test_payload_change_namespace_and_array_order_change_identity() -> None:
    first = {"artifact_sha256": "a" * 64, "order": [1, 2]}
    before = copy.deepcopy(first)
    original = deterministic_id("synthetic-v1", first)
    assert first == before
    assert deterministic_id("synthetic-v2", first) != original
    first["order"].reverse()
    assert deterministic_id("synthetic-v1", first) != original
    first["artifact_sha256"] = "b" * 64
    assert deterministic_id("synthetic-v1", first) != deterministic_id(
        "synthetic-v1", {**first, "artifact_sha256": "a" * 64}
    )
    assert deterministic_id("synthetic-v1", 1) != deterministic_id("synthetic-v1", 1.0)


@pytest.mark.parametrize("payload", [
    {1: "not-a-string-key"}, {"nested": {False: 1}}, (1, 2), {1, 2}, b"bytes",
    float("nan"), float("inf"), -float("inf"), {"nested": [float("nan")]}, object(),
])
def test_non_json_payload_rejected(payload: object) -> None:
    with pytest.raises(ValueError):
        canonical_json_bytes(payload)


def test_cycles_rejected_but_reused_noncyclic_values_allowed() -> None:
    shared = [1]
    assert canonical_json_bytes([shared, shared]) == b"[[1],[1]]"
    cycle = []
    cycle.append(cycle)
    with pytest.raises(ValueError, match="cycles"):
        canonical_json_bytes(cycle)


@pytest.mark.parametrize("namespace", ["", " leading", "Upper", "a:b", "../file", "x\n", None])
def test_invalid_namespace_rejected(namespace: object) -> None:
    with pytest.raises(ValueError, match="namespace"):
        deterministic_id(namespace, {})
