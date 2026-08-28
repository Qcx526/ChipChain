"""Offline loading for structured public-CVE corpus snapshots."""

from __future__ import annotations

from pathlib import Path

from chipchain.corpus.models import PublicCveCorpus


def load_public_cve_corpus(path: str | Path) -> PublicCveCorpus:
    """Read and validate one local corpus file without network access."""

    return PublicCveCorpus.model_validate_json(
        Path(path).read_text(encoding="utf-8")
    )
