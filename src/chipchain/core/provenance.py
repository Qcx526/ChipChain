"""Immutable byte-artifact provenance declarations, without truth judgments."""

import re

from pydantic import field_validator

from chipchain.core.architecture import Architecture
from chipchain.core.models import DomainModel, Identifier


class ArtifactProvenance(DomainModel):
    """Describe an artifact without opening files or authenticating a producer.

    The SHA-256 is mandatory but caller-declared. Future consumers must verify it
    against the exact bytes they consume. ``artifact_id`` is a stable source token,
    not an automatically generated digest or a filesystem path.
    """

    artifact_id: Identifier
    artifact_sha256: str
    source_kind: Identifier
    architecture: Architecture | None = None
    producer_profile_id: Identifier | None = None

    @field_validator("artifact_sha256", mode="before")
    @classmethod
    def normalize_sha256(cls, value: object) -> str:
        """Require exactly 64 hexadecimal characters; serialize lowercase."""

        if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
            raise ValueError("artifact SHA-256 must be exactly 64 hex characters")
        return value.lower()
