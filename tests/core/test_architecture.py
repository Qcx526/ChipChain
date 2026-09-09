"""Architecture labels express vocabulary, not installed analysis capabilities."""

import pytest
from pydantic import TypeAdapter, ValidationError

from chipchain.core import Architecture


@pytest.mark.parametrize(
    ("label", "member"), [("riscv", Architecture.RISC_V), ("arm", Architecture.ARM)]
)
def test_architecture_vocabulary_roundtrip(label: str, member: Architecture) -> None:
    adapter = TypeAdapter(Architecture)
    assert adapter.validate_python(label) is member
    assert adapter.validate_json(adapter.dump_json(member)) is member


@pytest.mark.parametrize("label", ["", "unknown", "RISC-V", "risc_v", "ARM"])
def test_unregistered_architecture_requires_explicit_extension(label: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(Architecture).validate_python(label)


def test_vocabulary_has_no_backend_support_claim() -> None:
    assert TypeAdapter(Architecture).json_schema()["enum"] == ["riscv", "arm"]
    for member in Architecture:
        for field in ("backend", "supported", "decoder", "parse", "analyze"):
            assert not hasattr(member, field)
