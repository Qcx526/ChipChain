"""Byte-backed provenance is mandatory, immutable, and non-evaluative."""

import pytest
from pydantic import ValidationError

from chipchain.core import Architecture, ArtifactProvenance


def test_sha_normalization_optional_architecture_and_roundtrip() -> None:
    payload = {
        "artifact_id": "synthetic-artifact-v1", "artifact_sha256": "Ab" * 32,
        "source_kind": "synthetic", "architecture": "riscv",
        "producer_profile_id": "synthetic-producer-v1",
    }
    source = ArtifactProvenance.model_validate(payload)
    payload["artifact_id"] = "caller-changed"
    assert source.artifact_id == "synthetic-artifact-v1"
    assert source.artifact_sha256 == "ab" * 32
    assert source.architecture is Architecture.RISC_V
    assert ArtifactProvenance.model_validate_json(source.model_dump_json()) == source
    generic = ArtifactProvenance(
        artifact_id="synthetic-data", artifact_sha256="0" * 64, source_kind="synthetic",
    )
    assert generic.architecture is None
    assert generic.producer_profile_id is None
    with pytest.raises(ValidationError, match="frozen_instance"):
        source.artifact_sha256 = "b" * 64


@pytest.mark.parametrize("sha", ["", "a" * 63, "a" * 65, "g" * 64,
                                "0x" + "a" * 64, "a" * 64 + "\n", None, 123])
def test_invalid_sha_rejected(sha: object) -> None:
    with pytest.raises(ValidationError, match="SHA-256"):
        ArtifactProvenance(artifact_id="synthetic", artifact_sha256=sha, source_kind="synthetic")


def test_sha_is_mandatory() -> None:
    with pytest.raises(ValidationError, match="artifact_sha256"):
        ArtifactProvenance(artifact_id="synthetic", source_kind="synthetic")


@pytest.mark.parametrize("field", ["verified", "verification_status", "vulnerability_status",
                                  "confidence", "trust_score", "llm_judgment", "path"])
def test_no_verdict_or_host_path_fields(field: str) -> None:
    assert field not in ArtifactProvenance.model_fields
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ArtifactProvenance.model_validate({
            "artifact_id": "synthetic", "artifact_sha256": "a" * 64,
            "source_kind": "synthetic", field: "forbidden",
        })
