"""Strictness, detachment, and immutable fields for future V2 contracts."""

import pytest
from pydantic import ValidationError

from chipchain.core import ArtifactProvenance, DomainModel, Identifier


class SyntheticEnvelope(DomainModel):
    """Test-only container with an immutable collection of nested models."""

    sources: tuple[ArtifactProvenance, ...]


class SyntheticToken(DomainModel):
    value: Identifier


def test_extra_fields_rejected() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        DomainModel(unexpected=True)


@pytest.mark.parametrize("value", ["", " ", "two words", " leading", "trailing ",
                                  "token\n", "/tmp/file", "../file", 1, b"token"])
def test_identifier_rejects_ambiguous_tokens(value: object) -> None:
    with pytest.raises(ValidationError):
        SyntheticToken(value=value)


def test_input_detachment_and_nested_revalidation() -> None:
    source = ArtifactProvenance(
        artifact_id="synthetic-source", artifact_sha256="a" * 64,
        source_kind="synthetic",
    )
    caller_sources = [source]
    retained = SyntheticEnvelope(sources=caller_sources)
    before = retained.model_dump_json()
    assert retained.sources[0] is not source
    caller_sources.clear()
    with pytest.raises(ValidationError, match="frozen_instance"):
        source.artifact_id = "changed"
    # Deliberately bypass frozen assignment on the caller-owned source.
    object.__setattr__(source, "artifact_sha256", "invalid")
    assert retained.model_dump_json() == before
    assert SyntheticEnvelope.model_validate_json(before) == retained
    with pytest.raises(ValidationError, match="SHA-256"):
        SyntheticEnvelope(sources=[source])


def test_repeated_serialization_has_no_generated_state() -> None:
    model = SyntheticToken(value="synthetic-token-v1")
    assert model.model_dump() == {"value": "synthetic-token-v1"}
    assert {model.model_dump_json() for _ in range(10)} == {
        '{"value":"synthetic-token-v1"}'
    }
