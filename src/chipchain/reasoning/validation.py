"""Shared verification-claim boundary for every semantic reasoning stage."""

from __future__ import annotations

from collections.abc import Iterable

from chipchain.reasoning.errors import LLMOutputValidationError

FORBIDDEN_VERIFICATION_CLAIMS = (
    "verified attack chain",
    "vulnerability confirmed",
    "exploit confirmed",
    "privilege escalation confirmed",
)


def validate_verification_boundary(texts: Iterable[str]) -> None:
    """Reject explicit verification claims in any model-authored free text."""

    searchable_text = " ".join(texts).lower()
    if any(claim in searchable_text for claim in FORBIDDEN_VERIFICATION_CLAIMS):
        raise LLMOutputValidationError(
            "provider output contains a forbidden verification claim"
        )
