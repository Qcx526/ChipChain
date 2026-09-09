"""Numerical normalization without implicit address-space or execution claims."""

import pytest
from pydantic import ValidationError

from chipchain.core import ProgramAddress


@pytest.mark.parametrize(("value", "expected"), [
    ("0x00001000", "0x1000"), ("0X1000", "0x1000"), ("0x0000", "0x0"),
    ("0XAbCD", "0xabcd"), ("0x10000000000000000", "0x10000000000000000"),
])
def test_normalization_and_roundtrip(value: str, expected: str) -> None:
    address = ProgramAddress(value=value)
    assert address.model_dump() == {"value": expected}
    assert ProgramAddress.model_validate_json(address.model_dump_json()) == address


@pytest.mark.parametrize("value", [
    "", " ", "4096", 4096, -1, "-0x1", "0x-1", "0x", "0xGG", " 0x1", "0x1\n",
    "+0x1", "0x1_000", None, True, b"0x1",
])
def test_malformed_address_rejected(value: object) -> None:
    with pytest.raises(ValidationError, match="non-negative hex"):
        ProgramAddress(value=value)


def test_address_is_frozen_and_cannot_assert_execution() -> None:
    address = ProgramAddress(value="0x1000")
    with pytest.raises(ValidationError, match="frozen_instance"):
        address.value = "0x2000"
    assert set(ProgramAddress.model_fields) == {"value"}
    for field in ("mmio", "executed", "memory_access", "physical", "virtual"):
        with pytest.raises(ValidationError, match="extra_forbidden"):
            ProgramAddress.model_validate({"value": "0x1000", field: True})
